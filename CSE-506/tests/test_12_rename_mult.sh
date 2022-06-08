echo "changes tmpin1 to tmpin2"
echo "file_2_data" >> tmpin1
echo "file_3_data" >> tmpin2
ls -l tmp*
./jobmanager -i -r tmpin1 tmpout1 tmpin2 tmpout2 -l -p
ls -l tmp*
rm tmpin1 tmpin2 tmpout1 tmpout2
