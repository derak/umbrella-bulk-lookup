#!/usr/bin/python

# This will need the investigate module installed via 'pip install investigate'.
import investigate, fileinput, sys, os, time, re

# Use this later to slice up a list.
def slice(l, n):
    n = max(1, n)
    return [l[i:i + n] for i in range(0, len(l), n)]

# Read API token key, single line
with open('api-key.txt', 'r') as k:
    api_key = k.read().rstrip()

# Instantiate the API with that token key.
inv = investigate.Investigate(api_key)

# Initialize list.
domains=[]

# Uncomment out the next line if the file has a second column for a hit count.
# hitcount={}

# Read the filename from the command line.
if len(sys.argv) == 2:
    filename = sys.argv[1]
else:
    # No filename then stop.
    print('ERROR: please provide an input file name')
    sys.exit(1)

with open(filename) as f:

    # Read one line at a time and keep just the hostname or IP address.
    for line in f:

        # Just the hostname or IP. No URLs, port numbers, quotes or anything
        line=line.replace('\n', '')
        linedomain=line.split(',')[0].strip('\n')
        linedomain=re.sub(r'\"', '', linedomain)
        linedomain=re.sub(r'^http\:\/\/', '', linedomain)
        linedomain=re.sub(r'^https\:\/\/', '', linedomain)
        linedomain=re.sub(r'\:.*$', '', linedomain)
        linedomain=re.sub(r'\/.*$', '', linedomain)

        # Uncomment out the next line if the file has a second column for a hit count.
        # hitcount[linedomain]=line.split(',')[1].strip('\n')

        # Ignore any single word entries in the file, that's not a FQDN or IP address.
        if linedomain.find('.')!=-1:
            if linedomain not in domains:
                domains.append(linedomain)

# Slice up the domains into chunks for bulk processing.
slices=slice(domains,1000)

# How many chunks do we need?
size = len(domains)
chunks = size/1000

# Don't forget about the remainder.
if (size%1000): chunks=chunks+1

# Print first line of CSV output
print('Destination,Status,Content Category,Security Category,Blocked Since,First Seen,Last Seen')

# Uncomment this next line if you have a hit count column and comment out the above line
# print('Destination,Status,Hit Count,Content Category,Security Category,Blocked Since,First Seen,Last Seen')

# Sending to the Investigate API one at a time is inefficient and takes forever.
# Bulk the information into 1000 entries for each API call.
for chunk in range(0, chunks):

    # Call to Investigate bulk REST endpoint.
    results = inv.categorization(slices[chunk], labels=True)

    for domain, value in results.items():

        # Some of the domains in the file may be unicode, handle that here.
        domain=domain.encode('utf-8')

        # De-link the domains on output and replace the last . with [.]
        domain_safe=domain.split('.')
        domain_end=domain_safe[-1]
        domain_safe=domain_safe[:-1]
        sys.stdout.write('.'.join(domain_safe))
        sys.stdout.write('[.]'+domain_end)
        sys.stdout.write(',')

        # Print Status
        sys.stdout.write(str(value['status'])+',')

        # Uncomment this line out to report on the hit count.
        # sys.stdout.write(str(hitcount[domain])+',')

        # This returns content_categories, security_categories, and status.
        # The status we don't care about here. Walk through and get the results.
        for category, categories in value.items():

            if category == 'content_categories':

                # Since we're already using ',' to delineate columns separate the categories using '|'.
                sys.stdout.write('|'.join(str(p) for p in categories))
                sys.stdout.write(',')

            # If the hostname or IP does not have a security category then print 'Benign'.
            # This gives you output that can be excluded or sort easily.
            if category == 'security_categories':
                if not categories:
                    sys.stdout.write('Benign')
                    print

                else:

                    # If we do have a security category then pull down the time line array and
                    # print the first date we blocked it from.

                    # Since we're already using ',' to delineate columns separate the categories using '|'.
                    sys.stdout.write('|'.join(str(p) for p in categories))

                    # The next two API calls are not bulked and will take more time to do this one
                    # entry at a time.

                    # Security categories have a time line and use requests python module to pull it down.
                    security_timeline = inv.timeline(domain)

                    # Format the timeline into a date
                    if (security_timeline != []) and (security_timeline[0]['timestamp'] is not None):
                        sys.stdout.write( ',' + time.strftime('%Y-%m-%d', time.localtime(security_timeline[0]['timestamp']/1000)))
                    else:
                        # If the timeline is empty
                        sys.stdout.write(',')

                    # Get the first seen and last seen date on hostnames only.
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",domain) is None:
                        security_history = inv.rr_history(domain)

                        # If there is first and last seen dates then print them.
                        if security_history['rrs_tf']:
                            sys.stdout.write(',' + security_history['rrs_tf'][0]['first_seen'])
                            sys.stdout.write(',' + security_history['rrs_tf'][0]['last_seen'])
                        else:
                            # If not print empty place holders
                            sys.stdout.write(',,')

                    # Were done with this line.
                    print

            # Flush the queue and display the line before the next.
            sys.stdout.flush()
