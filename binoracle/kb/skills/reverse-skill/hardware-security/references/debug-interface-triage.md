# Debugging Interface Diagnosis

1. Identify the pins: TX RX GND VCC TDI TDO TCK TMS  
2. Match voltage and then connect  
3. Start with read-only serial log  
4. Record U-Boot interrupt key and environment variables (do not saveenv arbitrarily)  
5. Extract the image and calculate SHA256