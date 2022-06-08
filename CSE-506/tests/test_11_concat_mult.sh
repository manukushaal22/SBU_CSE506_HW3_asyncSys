echo "file_1_data" >> tmpin1
echo "file_2_data" >> tmpin2
echo "file_3_data" >> tmpin3
./jobmanager -i -a tmpin1 tmpin2 tmpin3 tmpout -l -p
echo "After Concat"
cat tmpout
rm tmpin1 tmpin2 tmpin3 tmpout
