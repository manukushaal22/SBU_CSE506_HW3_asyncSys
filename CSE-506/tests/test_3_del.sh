echo "randomtext" >> tmpin
ls -l tmpin
./jobmanager -i -x tmpin -l -p
rm tmpin
