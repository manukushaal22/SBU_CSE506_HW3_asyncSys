echo "file_2_data" >> tmpin1
echo "file_1_data" >> tmpin2
cat tmpin1
cat tmpin2
./jobmanager -i -a tmpin1 tmpin2 tmpout -l -p
echo "After Concat"
cat tmpout
rm tmpin1 tmpin2 tmpout
