import sys
import binascii

def isLanguage(inBytes, low, high):
	if (int(binascii.hexlify(inBytes), 16) in range(low, high)):
		return True
	else:
		return False

def isAscii(byte):
	if (int(binascii.hexlify(byte), 16) in range(0x20, 0x7e)):
		return True
	else:
		return False

def checkAscii(fname):
	# strings is used to hold all possible strings
	strings = []
	f = open(fname, "rb")
	# setting prevByte to arbitrary value
	prevByte = '01' 
	byte = f.read(1)
	# while we haven't reached the end of the file
	while (byte != ""):
		# if the last character we looked at was Ascii, check to see if we have more Ascii to append to the string
		if isAscii(prevByte):
			if isAscii(byte):
				strings[-1] += chr(int(binascii.hexlify(byte), 16))
		# if we're seeing an Ascii character that will be the beginning of a new potential string
		else:
			if isAscii(byte):
				strings.append(chr(int(binascii.hexlify(byte), 16)))
		prevByte = byte
		byte = f.read(1)
	# now just return the strings that are 4 or more characters long
	return [x for x in strings if (len(x) > 3)]


def checkEvens(fname, low, high):
	# strings is used to hold all possible strings
	strings = []
	f = open(fname, "rb")
	# setting prevByte to arbitrary value
	prevBytes = '0000' 
	inBytes = f.read(2)
	# while we haven't reached the end of the file
	while (inBytes != ""):
		# if the last character we looked at was Ascii, check to see if we have more Ascii to append to the string
		if isLanguage(prevBytes, low, high):
			if isLanguage(inBytes, low, high):
				strings[-1] += "\u{0}".format(binascii.hexlify(inBytes))
		# if we're seeing an Ascii character that will be the beginning of a new potential string
		else:
			if isLanguage(inBytes, low, high):
				strings.append("\u{0}".format(binascii.hexlify(byte)))
		prevBytes = inBytes
		inBytes = f.read(2)
	# now just return the strings that are 4 or more characters long
	#print strings
	return [x for x in strings if (len(x) > 3)]


def checkOdds(fname, low, high):
	# strings is used to hold all possible strings
	strings = []
	f = open(fname, "rb")
	# setting prevByte to arbitrary value
	prevBytes = '0000' 
	# read the first byte to put us at an odd offset
	inBytes = f.read(1)
	# now start reading 2 bytes at a time
	inBytes = f.read(2)
	# while we haven't reached the end of the file
	while (inBytes != ""):
		# if the last character we looked at was Ascii, check to see if we have more Ascii to append to the string
		if isLanguage(prevBytes, low, high):
			if isLanguage(inBytes, low, high):
				strings[-1] += "\u{0}".format(binascii.hexlify(inBytes))
		# if we're seeing an Ascii character that will be the beginning of a new potential string
		else:
			if isLanguage(inBytes, low, high):
				strings.append("\u{0}".format(binascii.hexlify(byte)))
		prevBytes = inBytes
		inBytes = f.read(2)
	# now just return the strings that are 4 or more characters long
	# print strings
	return [x for x in strings if (len(x) > 3)]


def checkLanguage(fname, low, high):
	evens = []
	odds = []
	evens = checkEvens(fname, low, high)
	odds = checkOdds(fname, low, high)
	#print evens + odds, len(evens + odds)
	return evens + odds

def main(fname):
	asciiStrings = checkAscii(fname)
	languages = {'Cyrillic': {'Low':0x0400, 'High':0x04FF}}
	languageResults = {}
	# iterate through each language
	for language in languages:
		low = languages[language]['Low']
		high = languages[language]['High']
		languageResult = checkLanguage(fname, low, high)
		if (len(languageResult) > 0):
			languageResults[language] = languageResult

	# only display strings if they are 4 or more characters long
	for entry in asciiStrings:
		print entry
	for lang in languageResults:
		print language, languageResults[language]

if __name__ == '__main__':
	fname = sys.argv[1]
	main(fname)
