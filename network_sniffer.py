import os
import time
import datetime

def empty_folder(folder):
	for the_file in os.listdir(folder):
	    file_path = os.path.join(folder, the_file)
	    try:
	        if os.path.isfile(file_path):
	            os.unlink(file_path)
	    except Exception, e:
	        print e


raw_dump_dir = "./dumps"
parsed_dump_dir = "./parsed_dumps"
dump_name = "dump"
command = "tcpdump -w %s -C 1" % dump_name
bucket = "s3://metamx-james-selfserve/network_sniffing_aws/"

try:

	empty_folder(raw_dump_dir)

	os.system(" cd %s && sudo %s &" % (raw_dump_dir, command))
	print "hello"

	while True:
		time.sleep(10)
		files = os.listdir(raw_dump_dir)
		sorted_files = sorted(files, key = lambda filename: int(filename[len(dump_name):] + "0"))
		for filename in sorted_files[:-1]:
			file_timestamp = datetime.datetime.now().isoformat()
			output_name = "%s-%s" % (filename, file_timestamp)
			os.system("./pcap_parse %s/%s > %s/%s" % (raw_dump_dir, filename, parsed_dump_dir, output_name))
			print "Parsed file %s" % filename
			os.remove("%s/%s" % (raw_dump_dir, filename))
			print "Pushing file to S3"
			os.system("s3cmd put %s/%s %s" % (parsed_dump_dir, output_name , bucket))


			

except Exception as e:
	print e.stackTrace()

finally:
	print "Terminating tcpdump"
	kill_command = """kill `ps aux | grep "%s$" | awk '{print $2}'`""" % command
	os.system(kill_command)


