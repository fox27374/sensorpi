#!/usr/bin/python

print "Content-type:text/html\r\n\r\n"
print '<html>'
print '<head>'
print '<title>SensorPi Control</title>'
#print '<link rel="stylesheet" href="table.css">'
print '</head>'
print '<body>'
print '<div class="wrapper">'
print '<div class="navbar">'
print '<h1 style="color: white;">Jahreskarten Boulderhalle ('
#print dklib.get_mysql_count(id_event)
print ')</h1>'
print '<a class="buttonDownload" href="files/file0001.csv" download="Jahreskarten.csv">Download CSV</a>'
print '</div>'
#print dklib.db_to_html(id_event)
print '</div>'
print '</body>'
print '</html>'

