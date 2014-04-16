from settings_development import *
try:
    from settings_production import *
except:
    print "-" * 50
    print "Production Settings File Not Found"
    print "-" * 50