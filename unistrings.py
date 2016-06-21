#!/usr/bin/env python

__description__ = 'Look for strings in foreign language unicode'
__author__ = 'KB'
__date__ = '2016/06/15'

"""

I am only implementing an idea of those smarter than myself. All credit goes out to the Bigfoot Particle.
It is currently not optimal from a performance-perspective, but works. Use at your own risk.

Usage: python unistrings.py <parameters>

Parameters:
	-f <filename>  (required)
	-s   - shows currently supported languages and exits
	-a   - includes Ascii searches in the binary, similar to Linux 'strings' utility
	-l <language> - only display results for the specified language. If you are searching for multiple languages, input them separated by commas with no spaces (e.g. "-l Cyrillic,Hebrew,Greek")

"""


import sys
import binascii
import argparse


class Language:
	def __init__(self):
		# init stuffa 
		self.languages = {'Cyrillic': {'Low':0x0400, 'High':0x052F}, 'LatinExtendedA': {'Low': 0x0100, 'High':0x017F}, 'LatinExtendedB': {'Low':0x0180, 'High':0x024F}, 'GreekCoptic': {'Low':0x0370, 'High':0x03FF}, 'Armenian': {'Low':0x0530, 'High':0x058F}, 'Hebrew': {'Low':0x0590, 'High':0x05FF}, 'Arabic':{'Low':0x0600, 'High':0x06FF}, 'Syriac': {'Low':0x0700, 'High':0x074F}, 'Thaana': {'Low':0x0780, 'High':0x07BF}, 'Devanagari':{'Low':0x0900, 'High':0x097F}, 'Bengali':{'Low':0x0980, 'High':0x09FF}, 'Gurmukhi':{'Low':0x0A00, 'High':0x0A7F}, 'Thai':{'Low':0x0E00, 'High':0x0E7F}, 'Lao':{'Low':0x0E80, 'High':0x0EFF}, 'Tibetan':{'Low':0x0F00, 'High':0x0FFF}, 'Georgian':{'Low':0x10A0, 'High':0x10FF}, 'Hangul Jamo':{'Low':0x1100, 'High':0x11FF}, 'Greek':{'Low':0x1F00, 'High':0x1FFF}, 'Kangxi':{'Low':0x2F00, 'High':0x2FDF}, 'Katakana':{'Low':0x30A0, 'High':0x30FF}, 'Hangul':{'Low':0xAC00, 'High':0xD7AF}}

	def showLanguages(self):
		for lang in self.languages:
			print lang

	def getLanguage(self, dbyte):
		# inputs a double byte and checks/returns which language unicode range it is in.
		# returns 'Not Found' if no supported language can be found
		found = 'Not Found'
		for lang in self.languages:
			if (dbyte in range(self.languages[lang]['Low'], self.languages[lang]['High'])):
				found = lang
		return found

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


def main(args):
	i = 0    # byte counter
	fname = args.fname
	asciiStrings = []
	lang = Language()
	# first we build our list of Ascii strings if the Ascii flag is enabled
	if (args.asc):
		asciiStrings = checkAscii(fname)
	
	# languageResults stores the language, byte-location for strings, as well as the strings themselves
	languageResults = {}

	# open file and start reading bytes
	f = open(fname, "rb")
	# setting prevByte to arbitrary initial value
	prevByte = '0' 
	inByte = binascii.hexlify(f.read(1))
	# increase our counter to account for reading the initial byte
	i += 1
	# while we haven't reached the end of the file
	while (inByte != ""):
		# if the last character we looked at was within our range, check to see if we have more unicode to append to the string
		currBytes  = '{0}{1}'.format(prevByte, inByte)
		byteLang = lang.getLanguage(int(currBytes, 16))
		if (byteLang != 'Not Found'):
			# if this is the first time we're seeing a potential string for a language
			if byteLang not in languageResults:
				languageResults[byteLang] = {i: '\u{0}'.format(currBytes)}
			# else, if we've seen this language before, we need to check if this is an extension to an existing string, which we can tell by the byte count
			if ((i-3) in languageResults[byteLang]):
				languageResults[byteLang][i-1] = '{0}\u{1}'.format(languageResults[byteLang][i-3], currBytes)
				# now that we've updated our string, we can remove the old version
				languageResults[byteLang].pop(i-3)
			else:
				#otherwise we're starting a new string at this byte index
				languageResults[byteLang][i-1] = '\u{0}'.format(currBytes)
		# update our byte counter as we iterate to the next byte
		prevByte = inByte
		inByte = binascii.hexlify(f.read(1))
		i += 1

	# only display strings if they are 4 or more characters long
	for entry in asciiStrings:
		print entry
	for lang in languageResults:
		results = []
		if (args.lang):
			# if they specified a language
			if (lang in args.lang):
				for counter in languageResults[lang]:
					# if we have a string long enough to equal 4 unicode characters
					if (len(languageResults[lang][counter]) > 12):
						results.append(languageResults[lang][counter])	
		else:
			# if they didn't specify a language, just show all
			for counter in languageResults[lang]:
				if (len(languageResults[lang][counter]) > 12):
					results.append(languageResults[lang][counter])	
		if len(results) > 0:
			print "{0} - {1} strings".format(lang, len(results))
			for value in results:
				print value.decode('unicode-escape')
		# line break to separate languages	

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", "--filename", dest='fname', required=True, help="File to extract strings from")
	parser.add_argument("-a", "--ascii", dest='asc', action='store_true', help="Enable dumping of ascii characters")
	parser.add_argument("-s", "--showLanguages", dest='showLangs', action='store_true', help="Enable flag to list currently supported languages.")
	parser.add_argument("-l", "--language", dest='lang', help="Comma separated list of languages that you are specifically looking for in a file. Other potential languages will not be shown.")
	args = parser.parse_args()
	if (args.showLangs):
		lang = Language()
		lang.showLanguages()
		sys.exit()
	else:
		main(args)
