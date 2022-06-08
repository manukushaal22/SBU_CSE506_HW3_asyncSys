echo "changes tmpin1 to tmpin2"
echo "file_2_data" >> tmpin1
ls -l tmp*
./jobmanager -i -r tmpin1 tmpin2 -l -p
ls -l tmp*
rm tmpin1 tmpin2
