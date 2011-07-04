include $(GOROOT)/src/Make.inc

TARG=crypto/bcrypt
GOFILES=bcrypt.go base64.go cipher.go

include $(GOROOT)/src/Make.pkg
