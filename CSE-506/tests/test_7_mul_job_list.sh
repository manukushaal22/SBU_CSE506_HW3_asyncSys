echo "randomdata" >> inf.txt
./jobmanager -i -c inf.txt out.txt -l -f
./jobmanager -i -c inf.txt out.txt -l -f
./jobmanager -i -c inf.txt out.txt -f
./jobmanager -l -l
./jobmanager -i -c inf.txt out.txt -l -f
./jobmanager -i -c inf.txt out.txt -l -f
./jobmanager -i -c inf.txt out.txt -l -f
./jobmanager -l -l
rm inf.txt out.txt
