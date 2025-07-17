ReadMe for DEVScan_dom_snapshot_withcsv

Things need to check in the code
 *concurrencyLimit - refers to the number of link the system may run (the higher the faster but prone to error)
		- try 10 first if some errors occur change it to lower

Step on how to use the system:
Step1:
   Get a certain amount of link in the url_with_label folder preferably 1000-2000 per session

Step2:
   Paste the acquired link to the upload folder under the link.csv 
   Note:
	-Dont put a link of the first row and it should only contain url and label

Step3:
   Open the system terminal and run "npm run batch" this will automatically get the latest csv in the upload folder and scanned all the links inside
   Note:
	If certain errors where it automatically stop the scanning try to lower your concurrencyLimit and number of link inside the link.csv

Important thing to remember:
   -If the system encountered a error where it leads to automatically stop of the system the prior scanned links will not be saved to the csv
   -The system will automatically save the gathered features in the dom-dataset.csv. If the output folder didn't have dom-dataset.csv the system will automatically make one
   -The system will make a csv every scanning session the user make for error happened (kailangan ko yun pa compile na lang HAHAHAHAHA)
   -Every scanning session try to make a backup of the dom-dataset.csv like copy paste nyo lang sya sa ibang folder para incase of error hindi madamay lahat


Distribution of Work for this week:
Klarence: first 2 - 100,000 links in the url_with_label.csv
Aldwin: first 100,001 - 200,000k links in the url_with_label.csv
Ernest: first 200,001 - 300,001k links in the url_with_label.csv

Rjay: Start ka sa pinaka dulo pataas wala ka ng quota medyo computational heavy kasi pero sana Kahit 25,000 - 50,000 links this week
   - babaan mo concurrencyLimit mo 3 siguro and mag 500 links per session ka lang