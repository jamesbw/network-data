import os
import time
import datetime
import subprocess
import random
import csv
import pygeoip

gi_v4 = pygeoip.GeoIP('./GeoLiteCity.dat')
gi_v6 = pygeoip.GeoIP('./GeoLiteCityv6.dat')

def empty_folder(folder):
	for the_file in os.listdir(folder):
	    file_path = os.path.join(folder, the_file)
	    try:
	        if os.path.isfile(file_path):
	            os.unlink(file_path)
	    except Exception, e:
	        print e

# empty_folder(raw_dump_dir)


raw_dump_dir = "./dumps"
parsed_dump_dir = "./parsed_dumps"
geolocated_dump_dir = "./geolocated_dumps"
bucket = "s3://metamx-james-selfserve/network_sniffing/"

interface = None
ifaddr = "127.0.0.1"
running = False



def kill(command):
	print "Terminating tcpdump"
	kill_command = """kill `ps aux | grep "%s$" | awk '{print $2}'`""" % command
	os.system(kill_command)

def get_interface():
	return subprocess.check_output("route -n get default | grep interface | awk '{print $2}'", shell=True)[0:3]

def get_ifaddr(interface):
	return subprocess.check_output("ipconfig getifaddr %s" % interface, shell=True).strip()

def init(raw_dump_dir, interface):
	dump_name = "dump" + str(random.randint(10000, 99999))
	command = "tcpdump -w %s -i %s -C 1" % (dump_name, interface)
	print command
	os.system(" cd %s && sudo %s &" % (raw_dump_dir, command))
	return command, dump_name

def add_geolocation(input_path, output_path):
	fieldnames = ["Timestamp", "Ethernet Type", "IP Version", "Payload Bytes", "Source IP", "Destination IP", "Transport Protocol", "Source Port", "Destination Port", "My IP Address", "Incoming Traffic"]
	with open(input_path, 'r') as input_csv, open(output_path, 'w') as output_csv:
		reader = csv.DictReader(input_csv, fieldnames = fieldnames)
		writer = csv.DictWriter(output_csv, fieldnames = fieldnames + ['Destination Country', 'Destination City', 'Destination Longitude', 'Destination Latitude', 'Destination Region']
																   + ['Source Country', 'Source City', 'Source Longitude', 'Source Latitude', 'Source Region'])
#
		reader.next() #header
		writer.writeheader()
		for row in reader:
			try:
				# print row
				using_gi = None
				if row["IP Version"] == '4':
					using_gi = gi_v4
				if row["IP Version"] == '6':
					using_gi = gi_v6
				if using_gi:
					try:
						dst_record = using_gi.record_by_addr(row['Destination IP'])
					except:
						dst_record = None
						pass
					try:	
						src_record = using_gi.record_by_addr(row['Source IP'])
					except:
						src_record = None
						pass

					# print src_record
					# print dst_record
					if dst_record:
						row['Destination Country'] = dst_record['country_name']
						row['Destination City'] = dst_record['city']
						row['Destination Longitude'] = dst_record['longitude']
						row['Destination Latitude'] = dst_record['latitude']
						row['Destination Region'] = dst_record['region_name']
		#
					if src_record:
						row['Source Country'] = src_record['country_name']
						row['Source City'] = src_record['city']
						row['Source Longitude'] = src_record['longitude']
						row['Source Latitude'] = src_record['latitude']
						row['Source Region'] = src_record['region_name']
		#
				writer.writerow(row)
			except Exception as e:
				print e.stackTrace()
				continue

try:
	

	print "hello"

	while True:
		time.sleep(10)
		new_interface = get_interface()
		if new_interface not in ['en0', 'en1']:
			continue

		files = os.listdir(raw_dump_dir)
		if ".DS_Store" in files:
			files.remove(".DS_Store")
		sorted_files = sorted(files, key = lambda filename: int(filename[9:] + "0"))
		for filename in sorted_files[:-1]:
			file_timestamp = datetime.datetime.now().isoformat()
			parsed_output_name = "%s-%s" % (filename, file_timestamp)
			os.system("./pcap_parse %s/%s %s > %s/%s" % (raw_dump_dir, filename, ifaddr, parsed_dump_dir, parsed_output_name))
			print "Parsed file %s" % filename

			#geolocation
			geolocated_output_name = "geolocated-%s" % parsed_output_name
			add_geolocation("%s/%s" % (parsed_dump_dir, parsed_output_name), "%s/%s" % (geolocated_dump_dir, geolocated_output_name))

			print "Geolocated file %s" % parsed_output_name

			os.remove("%s/%s" % (raw_dump_dir, filename))
			print "Pushing file to S3"
			os.system("s3cmd put %s/%s %s" % (geolocated_dump_dir, geolocated_output_name , bucket))

		if interface != new_interface:
			interface = new_interface
			ifaddr = get_ifaddr(interface)
			if running:
				print "killing"
				kill(command)
			command, dump_name = init(raw_dump_dir, interface)
			running = True

			

except Exception as e:
	print 'exception'
	print e.stackTrace()

finally:
	print "finally"
	if running:
		kill(command)


