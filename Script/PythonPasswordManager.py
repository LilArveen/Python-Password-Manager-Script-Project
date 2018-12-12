#!/usr/bin/env python3

# coding: utf-8

import os
import csv

"""
Function below checks whether or not a master password is correct. Stat key,
key increment is needed to encrypt master password to check with actual encrypted
master password in user file. pwd is what the user inputted as the master password.
Checker is actual, encrypted master password that is passed in.

Parameters
----------
start_key: integer needed for encryption.
ke_increment: integer needed for encrption purposes
pwd: password user inputted
checker: actual master password

Returns:
-------
True if master password that was inputted was correct
False if master password is not correct
"""
def checkMwP(start_key, key_increment, pwd, checker):

    key = 0
    encoded = ""
    for char in pwd:
        key += ord(char)

    key+=len(pwd)
    key+= start_key

    #encoding inputted master password to check against actual master password.
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

"""
Class contains all custom classes needed for password manager. Contains key used
to encrypt user info, master password needed to login. Start key and key increment are
also included for encryption purposes.
"""
class pythonKey():

    def __init__(self, is_new_user, pwd):
        self.newUser = is_new_user

        #Update key used to encrypt/decrypt user information
        self.key = 0
        for char in pwd:
            self.key += ord(char)

        #Set master password used to login
        self.masterPwd = pwd

        #keys needed for encrypting master password and user information
        self.startKey = 150
        self.keyIncrement = 3

        #dictionary to store website and corresponding username/password
        self.pyKeyStructure = {}

    """
    Checks if user is new or not. if new, create user directory and files.
    """
    def checkDirectory(self):

        if(self.newUser):
            #pull up file and update
            directory = os.getcwd()
            directory+= '/pyPwdUsr'

            #check if user directory already exists.
            if(os.path.isdir(directory)):
                print("Detected previous user files.")
                print("Please delete those files if you wish to be a new user")
                print("Files are called pyPwdUsr")
                return False
            else:

                os.mkdir('pyPwdUsr')
                os.chdir('pyPwdUsr')
            return True

        else:
            #get user directory
            directory = os.getcwd()
            directory += "/pyPwdUsr"

            #checks if user directory exists.
            if(os.path.isdir(directory)):
                os.chdir('pyPwdUsr')

                #opens master password user file if it exists.
                with open('mwPd') as mwF:
                    mwPd = mwF.readline();
                    check = checkMwP(self.startKey, self.keyIncrement, self.masterPwd, mwPd)

                    #if master password is correct, read userinfo.
                    if check:
                        self.readUserFile("userInfo.csv")
                        return True
                    else:
                        print("Incorrect password; please try again")
                        return False
            else:
                print("Unable to find user files; please login as new user")
                return False


    """
    Decrypt info that is passed in using key passed in.
    Paramaters:
    ----------
    encoded: encoded information needed to decrypt
    key: needed for decoding purposes.

    Returns:
    decoded: string that is decoded
    """
    def decrypt(self, encoded, key):
        decoded = ""
        for char in encoded:
            unicode = ord(char)
            unicode -= key
            decoded += chr(unicode)
        return decoded

    """
    Encrypt info that is passed in using key passed in.
    Paramaters:
    ----------
    decoded: decoded information needed to encrypt
    key: needed for encoding purposes.

    Returns:
    encoded: string that is encoded
    """
    def encrypt(self, decoded, key):
        encoded = ""
        for char in decoded:
            unicode = ord(char)
            unicode += key
            encoded += chr(unicode)
        return encoded

    """
    adds new website and the corresponding username/password.
    Parameters:
    -----------
    website: string of website
    username: string of username
    password: string of password for website
    """
    def addNewSite(self, website, username, password):
        self.pyKeyStructure[website] = [username, password]


    """
    Reads in user information file if it exists already
    Parameters:
    -----------
    fileName: string of filename to read in
    """
    def readUserFile(self, fileName):
        username = ''
        password = ''
        website = ''

        #Reads in user info.
        with open(fileName) as csvFile:
            csvReader = csv.reader(csvFile, delimiter=',')
            for row in csvReader:

                website = self.decrypt(row[0], self.key)
                username = self.decrypt(row[1], self.key)
                password = self.decrypt(row[2], self.key)
                self.pyKeyStructure[website] = [username, password]


    """"
    encodes everything to user files.
    """
    def logout(self):
        #encode master password and input it to mwPd file
        key = 0
        encoded = ""
        for char in self.masterPwd:
            key += ord(char)

        key+=len(self.masterPwd)
        key+= self.startKey

        for char in self.masterPwd:
            unicode = ord(char)
            unicode+=key
            unicode %= 1114111
            encoded+=chr(unicode)
            key+= self.keyIncrement

        #input master password into mwPd file
        with open("mwPd", 'w+') as fileToWrite:
            print("writing files")
            fileToWrite.write(encoded)
            fileToWrite.close()

        #open user info file and encrypt information onto file.
        with open('userInfo.csv', 'w+') as csvFile:
            writer = csv.writer(csvFile)
            for key, value in self.pyKeyStructure.items():
                #encrypt all necessary items
                key = self.encrypt(key, self.key)
                value1 = self.encrypt(value[0], self.key)
                value2 = self.encrypt(value[1], self.key)
                writer.writerow([key, value1, value2])
        os.chdir("..")


    """
    Prints out all websites and the corresponding username/password
    """
    def viewAll(self):
        num = 0
        print("")
        for x in self.pyKeyStructure:
            print("Website: ", x, end = ' || ')
            for y in self.pyKeyStructure[x]:
                if(num == 0):
                    print("Username: ",y, end = ' || ')
                    num += 1
                else:
                    num -= 1
                    print("Password: ", y)


    """
    allows the user to view specified website username/password
    Paramaters:
    ----------
    website: name of website that needs to be modified.
    """
    def viewOne(self, website):
        print("")
        #check if website exists
        if website in self.pyKeyStructure.keys():
            #print out username and password
            num = 0
            for y in self.pyKeyStructure[website]:
                if(num == 0):
                    print("Username: ",y, end = ' || ')
                    num += 1
                else:
                    num -= 1
                    print("Password: ", y)

        else:
            print("Website not in manager.")

    """
    deletes specified website and it username/password
    Paramaters:
    ----------
    website: name of website that needs to be deleted.
    """
    def deleteWebsite(self, website):
        if website in self.pyKeyStructure:
            del self.pyKeyStructure[website]
            print("Deleted ", website)
        else:
            print("Website not found in manager")

    """
    updates password for corresponding website.
    Parameters:
    -----------
    website: name of website that needs to be updated
    new_password: string of new password.
    """
    def updateWebPassword(self, website, new_password):
        if website in self.pyKeyStructure:
            self.pyKeyStructure[website][1] = new_password
            print("Changes successful")
        else:
            print("Website not found in manager")

    """
    updates username for corresponding website.
    Parameters:
    -----------
    website: name of website that needs to be updated
    new_username: string of new username.
    """
    def updateWebUsername(self, website, new_username):
        if website in self.pyKeyStructure:
            self.pyKeyStructure[website][0] = new_username
            print("Changes successful")
        else:
            print("Website not found in manager")

    """
    updates master password
    Parameters:
    -----------

    new_master_password: string of new password.
    """
    def updateMasterPassword(self, new_master_password):
        self.masterPwd = new_master_password
        self.key = 0
        for char in new_master_password:
            self.key += ord(char)

"""
Controls login when script first starts.
"""
def login():
    print("Welcome to a python based password manager")
    print("Users can enter username and password of their choice, with the website url")


    print("")

    choice = input("Please enter master password (type new if new user): ")
    if choice == "new":
        pwd = input("Enter master password for new user: ")
        user = pythonKey(True, pwd)

    else:
        user = pythonKey(False, choice)

    return user


"""
Prints out commands and what each command does.
"""
def printCommands():
    print("\n[newWebsite] Enter new website to save.")
    print("[viewAll] view everything that is saved")
    print("[viewOne] view one website")
    print("[updateMasterPwd] update master password")
    print("[updatePwd] update password for individual website")
    print("[updateUName] update username for individual website")
    print("[delete] deletes a website")
    print("[q] Quit.")


#Actual driver of program starts below:
#pythonKey class initialized.
user = login()
#checks if applicable directories are needed or not.
while(not user.checkDirectory()):
    user = login()


print("\n[newWebsite] Enter new website to save.")
print("[viewAll] view everything that is saved")
print("[viewOne] view one website")
print("[updateMasterPwd] update master password")
print("[updatePwd] update password for individual website")
print("[updateUName] update username for individual website")
print("[delete] deletes a website")
print("[q] Quit.")
print("")
print("To display what each command does, type [help]")


choice = ''
while choice != 'q':
    # Let users know what they can do.

    print("Type [help] to see commands and what they do. ")

    choice = input("What would you like to do? ")

    # Responding to the user's choice.
    if choice == 'newWebsite':
        website = input("Enter new website: ")
        username = input("Enter corresponding username: ")
        password = input("Enter corresponding password: ")

        user.addNewSite(website, username, password)

    elif choice == 'viewAll':
        user.viewAll()

    elif choice == 'viewOne':
        website = input("Enter website you wish to view: ")
        user.viewOne(website)

    elif choice == 'updateMasterPwd':
        password = input("Enter new master password: ")
        user.updateMasterPassword(password)

    elif choice == 'updatePwd':
        website = input("Enter website: ")
        password = input("Enter new password: ")
        user.updateWebPassword(website, password)

    elif choice == 'updateUName':
        website = input("Enter website: ")
        username = input("Enter new username: ")
        user.updateWebUsername(website, username)

    elif choice == 'delete':
        website = input("Enter website you wish to delete: ")
        user.deleteWebsite(website)

    elif choice == 'help':
        printCommands()

    elif choice == 'q':
        user.logout()
        print("Thanks for using this. Bye.")

    else:
        print("Incorrect command. Please read instructions above")
