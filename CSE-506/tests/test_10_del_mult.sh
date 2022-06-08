echo "randomtext" >> tmpin
echo "randomtext" >> tmpin2
echo "randomtext" >> tmpin3
./jobmanager -i -x tmpin tmpin2 tmpin3 -l -p
rm tmpin tmpin2 tmpin3
