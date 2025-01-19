rm -rf /opt/PHANTX/smap

cp -Rf phantxbin/* /opt/PHANTX/bin/

chmod -R 755 /opt/PHANTX/bin/ 

cp -Rf $(pwd) /opt/PHANTX/smap 
