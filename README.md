Group Project: Blockchain Chain of Custody
Group 21
Jonathan Lin, Ryan Rajesh, Joshin Sam, Samay Sharma

The program generates a blockchain for a chain of custody. It stores the 
timestamp (regular unix timestamp)
case id (uuid) 
evidence item id 
creator
owner (police, lawyer, analyst, executive).

The following are commands to interact with the program
bchoc add -c case_id -i item_id [-i item_id ...] -g creator -p password(creator’s)
bchoc checkout -i item_id -p password
bchoc checkin -i item_id -p password
bchoc show cases 
bchoc show items -c case_id
bchoc show history [-c case_id] [-i item_id] [-n num_entries] [-r] -p password
bchoc remove -i item_id -y reason -p password(creator’s)
bchoc init
bchoc verify
