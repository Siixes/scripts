#!/usr/bin/env python

__description__ = 'Look for strings in foreign language unicode'
__author__ = 'KB'
__date__ = '2016/06/15'

"""

I am only implementing an idea of those smarter than myself. All credit goes out to the Bigfoot Particle.
It is currently not optimal from a performance-perspective, but works. Use at your own risk.

Usage: python unistrings.py <filename>

"""


import sys
import binascii

# isLanguage checks if a series of bytes is within a language range
def isLanguage(inBytes, low, high):
	if (int(binascii.hexlify(inBytes), 16) in range(low, high)):
		return True
	else:
		return False
# isAscii checks if a byte is within printable Ascii range
def isAscii(byte):
	if (int(binascii.hexlify(byte), 16) in range(0x20, 0x7e)):
		return True
	else:
		return False

# checkAscii builds a list of all Ascii strings in a file, similar to the Linux 'strings' utility
def checkAscii(fname):
	# strings is used to hold all possible strings
	strings = []
	f = open(fname, "rb")
	# setting prevByte to arbitrary value
	prevByte = '00' 
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

# checkLangBytes iterates through a file to build a list of strings that fall within a certain unicode character set
def checkLangBytes(fname, low, high, offset):
	# strings is used to hold all possible strings
	strings = []
	f = open(fname, "rb")
	# setting prevByte to arbitrary value
	prevBytes = '0000' 
	# if we're going through the 2nd run through, skip the first byte to look at an odd offset of bytes
	if (offset == 1):
		inBytes = f.read(1)
	inBytes = f.read(2)
	# while we haven't reached the end of the file
	while (inBytes != ""):
		# if the last character we looked at was within our range, check to see if we have more unicode to append to the string
		if isLanguage(prevBytes, low, high):
			if isLanguage(inBytes, low, high):
				strings[-1] += "\u{0}".format(binascii.hexlify(inBytes))
		# if we're seeing a correct Unicode character that will be the beginning of a new potential string
		else:
			if isLanguage(inBytes, low, high):
				strings.append("\u{0}".format(binascii.hexlify(inBytes)))
		prevBytes = inBytes
		inBytes = f.read(2)
	# now just return the strings that are 4 or more characters long, however, we're looking for over 11 characters to account for the whole unicode string
	return [x for x in strings if (len(x) > 11)]

# checkLanguage iterates over both the even and odd offsets of bytes in a file and combines lists of both offsets
def checkLanguage(fname, low, high):
	evens = checkLangBytes(fname, low, high, 0)
	odds = checkLangBytes(fname, low, high, 1)
	return evens + odds

def main(fname):
	# first we build our list of Ascii strings
	asciiStrings = checkAscii(fname)
	# list of supported languages
	languages = {'Cyrillic': {'Low':0x0400, 'High':0x052F}, 'LatinExtendedA': {'Low': 0x0100, 'High':0x017F}, 'LatinExtendedB': {'Low':0x0180, 'High':0x024F}, 'GreekCoptic': {'Low':0x0370, 'High':0x03FF}, 'Armenian': {'Low':0x0530, 'High':0x058F}, 'Hebrew': {'Low':0x0590, 'High':0x05FF}, 'Arabic':{'Low':0x0600, 'High':0x06FF}, 'Syriac': {'Low':0x0700, 'High':0x074F}, 'Thaana': {'Low':0x0780, 'High':0x07BF}, 'Devanagari':{'Low':0x0900, 'High':0x097F}, 'Bengali':{'Low':0x0980, 'High':0x09FF}, 'Gurmukhi':{'Low':0x0A00, 'High':0x0A7F}, 'Thai':{'Low':0x0E00, 'High':0x0E7F}, 'Lao':{'Low':0x0E80, 'High':0x0EFF}, 'Tibetan':{'Low':0x0F00, 'High':0x0FFF}, 'Georgian':{'Low':0x10A0, 'High':0x10FF}, 'Hangul Jamo':{'Low':0x1100, 'High':0x11FF}, 'Greek':{'Low':0x1F00, 'High':0x1FFF}, 'Kangxi':{'Low':0x2F00, 'High':0x2FDF}, 'Katakana':{'Low':0x30A0, 'High':0x30FF}, 'Hangul':{'Low':0xAC00, 'High':0xD7AF}}
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
		# if there are results in the language to print out
		if (len(languageResults[lang]) > 0):
			print "\n\n{0}".format(lang)
			for string in languageResults[lang]:
				print string.decode('unicode-escape')

if __name__ == '__main__':
	fname = sys.argv[1]
	main(fname)
