#!/usr/bin/env python3
# coding: utf-8

import pytest

def checkMwP(start_key, key_increment, pwd, checker):

    key = 0
    encoded = ""
    for char in pwd:
        key += ord(char)

    key+=len(pwd)
    key+= start_key

    for char in pwd:
        unicode = ord(char)
        unicode+=key
        unicode %= 1114111
        encoded+=chr(unicode)
        key+= key_increment

    if encoded != checker:
        return False
    else:
        return True


def testCheckMwP():
    assert checkMwP(150, 3, 'bob', 'ȮȾȴ') == True
    assert checkMwP(150, 3, 'bob', 'Ȯ') == False
    assert checkMwP(150, 3, 'NANI', 'ȎȄȔȒ') == True
    assert checkMwP(150,3, 'askfjan48281894%%%!23', 'ڋڠڛڙڠښڪٳٺٷڀټچڊڈټٿڂځڕڙ') == True


#deletes website and it's corresponding username/password.
def deleteWebsite(pyKeyStructure, website):
    if website in pyKeyStructure:
        del pyKeyStructure[website]
        print("Deleted ", website)
    else:
        print("Website not found in manager")

def testDeleteWebsite():
    pyKeyStructure = {'google':['a@gmail.com', 'bb'], 'facebook':['a@gmail.com', 'cc']}
    deleteWebsite(pyKeyStructure, 'google')
    assert ('google' in pyKeyStructure) == False
    deleteWebsite(pyKeyStructure, 'facebook')
    assert ('facebook' in pyKeyStructure) == False

#updates password with corresponding website.
def updateWebPassword(pyKeyStructure, website, new_password):
    if website in pyKeyStructure:
        pyKeyStructure[website][1] = new_password
        print("Changes successful")
    else:
        print("Website not found in manager")

def testupdateWebPassword():
    pyKeyStructure = {'google':['a@gmail.com', 'bb'], 'facebook':['a@gmail.com', 'cc']}
    updateWebPassword(pyKeyStructure, 'google', 'aa')
    assert pyKeyStructure['google'][1] == 'aa'
    assert pyKeyStructure['google'][1] != 'bb'
    updateWebPassword(pyKeyStructure, 'facebook', 'aldkfjaldkfjla')
    assert pyKeyStructure['facebook'][1] == 'aldkfjaldkfjla'
    assert pyKeyStructure['facebook'][1] != 'cc'

#updates password with corresponding username.
def updateWebUsername(pyKeyStructure, website, new_username):
    if website in pyKeyStructure:
        pyKeyStructure[website][0] = new_username
        print("Changes successful")
    else:
        print("Website not found in manager")

def testupdateWebUsername():
    pyKeyStructure = {'google':['a@gmail.com', 'bb'], 'facebook':['a@gmail.com', 'cc']}
    updateWebUsername(pyKeyStructure, 'google', 'aa')
    assert pyKeyStructure['google'][0] == 'aa'
    assert pyKeyStructure['google'][0] != 'a@gmail.com'
    updateWebUsername(pyKeyStructure, 'facebook', 'aldkfjaldkfjla')
    assert pyKeyStructure['facebook'][0] == 'aldkfjaldkfjla'
    assert pyKeyStructure['facebook'][0] != 'a@gmail.com'

#updates master password
def updateMasterPassword(masterPwd, new_master_password, key):
    masterPwd = new_master_password
    key = 0
    for char in new_master_password:
        key += ord(char)
    return [masterPwd, key]

def testUpdateMasterPassword():
    list1=['Bob', 275]

    list2 = updateMasterPassword(list1[0], 'Vinny', list1[1])
    assert list2[0] == 'Vinny'
    assert list2[1] == 532

    list2 = updateMasterPassword(list2[0], 'AZ1235$$#!@#', list2[1])
    assert list2[0] == 'AZ1235$$#!@#'
    assert list2[1] == 597


def decrypt(encoded, key):
    decoded = ""
    for char in encoded:
        unicode = ord(char)
        unicode -= key
        decoded += chr(unicode)
    return decoded

def encrypt(decoded, key):
    encoded = ""
    for char in decoded:
        unicode = ord(char)
        unicode += key
        encoded += chr(unicode)
    return encoded

def testEncryptAndDecrypt():
    decoded = 'WOW'
    key = 150
    assert decrypt(encrypt(decoded, key), key) == 'WOW'

#adds new website and the corresponding username/password.
def addNewSite(pyKeyStructure, website, username, password):
    pyKeyStructure[website] = [username, password]
    return pyKeyStructure

def testAddNewSite():
    pyKeyStructure = {}
    pyKeyStructure = addNewSite(pyKeyStructure, 'google', 'a@gmail.com', 'bb')
    assert ('google' in pyKeyStructure) == True
    assert pyKeyStructure['google'][1] == 'bb'
    assert pyKeyStructure['google'][0] == 'a@gmail.com'
    pyKeyStructure = addNewSite(pyKeyStructure, 'facebook', 'a@gmail.com', 'cc')
    assert ('facebook' in pyKeyStructure) == True
    assert pyKeyStructure['facebook'][1] == 'cc'
    assert pyKeyStructure['facebook'][0] == 'a@gmail.com'
