# conprov

The system consists of conprov and provData. conprov is used to generate the log of the specified container, and provData is responsible for preprocessing the log data and generating the provenance graph. Therefore, we need to run a docker container firstly, and then run conprov to monitor this specified container, and copy the generated log path to provData for processing. The libraries needed to run the system have been installed in the virtual machine. To verify the functionality of the system, follow these steps:

1. docker pull training/webapp
2. docker run --name test -d -P training/webapp python app.py
3. copy the Id : docker inspect (test) |grep Id
4. cd conprov && make all
5. sudo ./conprovd (you need input the Id)
6. Accessing the container's web service or interacting with it through a bash session will trigger the recording of relevant activities. For example, you can use `curl 127.0.0.1:32768` (where the port is a randomly assigned local port for the web container). 
7. To stop monitoring the container, press Ctrl+C. The log file will be saved in the `conprov` directory. You can then copy this log file to the `provData` folder and rename it to `conprov.log`.
6. cd ../provData
7. sudo apt-get install graphviz && python3 -m pip install -r requirements.txt
8. python3 spade_graph.py