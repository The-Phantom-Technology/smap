rm -rf /opt/PHANTX/smap/.git*

rm -rf /opt/PHANTX/smap

rm -rf .git*

cp -Rf phantxbin/* /opt/PHANTX/bin/

chmod -R 755 /opt/PHANTX/bin/ 

cp -Rf $(pwd) /opt/PHANTX/smap 
