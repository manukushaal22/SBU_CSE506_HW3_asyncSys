echo "hahaha" >> tmpin
./jobmanager -i -c tmpin tmpout -l -p
rm tmpin tmpout
