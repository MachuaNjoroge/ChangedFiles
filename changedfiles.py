
# Import database modules that will be used to create the tables if they don't exist and create SQLite db
from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean
from sqlalchemy import desc,asc,func
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base

from ast import walk
import os
import hashlib
import platform,socket,time
from datetime import datetime
import paramiko
import smtplib, ssl
from email.message import EmailMessage


engine = create_engine('sqlite:///changedfiles.db')
Base = declarative_base()

'''This class creates a table in the db if it does not exist. If it exists, it allows us to access the tables as object by instantiating it.'''
class BwServers(Base):
    __tablename__ = 'bwservers'
    # __talbleargs__ = {'schema':'landon'}

    server_id = Column(Integer,primary_key=True)
    server_ip = Column(String(30))
    server_hostname = Column(String(50))
    server_dc = Column(String(50))
    
    def __repr__(self): 
        return '''<BwServers(server_ip{0},server_hostname{1},server_dc{2})>'''.format(
            self.server_ip,self.server_hostname,self.server_dc,self.cust_state)

'''This class creates a table in the db if it does not exist. If it exists, it allows us to access the tables as object by instantiating it.'''
class FileHashes(Base):
    __tablename__ = 'file_hashes'
    # __talbleargs__ = {'schema':'landon'}

    file_id = Column(Integer,primary_key=True)
    server_id = Column(Integer)
    file_name = Column(String(300))
    file_hash = Column(String(50))
    updated = Column(String(5))
    
    def __repr__(self): 
        return '''<FileHases(file_name{0},file_hash{1},updated{2})>'''.format(self.file_name,self.file_hash,self.updated)

Base.metadata.create_all(engine)


'''This method return a session to be used to connect to the database'''
def loadSession():
    Session = sessionmaker(bind=engine)
    session = Session()
    return session

'''This method takes in a file and return its md5sum digest'''
def hash_file(file_name):
    try:
        return hashlib.md5(open(file_name,"rb").read()).hexdigest()
    except Exception as e:
        '''If file is a symbolic link, check if actual file referenced exists. If it does, compute a hash on it.If is doesn't return generic message. 
        is not a symbolic link but error is thrown return error as hash'''
        if os.path.islink(file_name):
            if os.path.isfile(file_name):
                return hashlib.md5(open(os.path.realpath(file_name),"rb").read()).hexdigest()
            else:
                return "file doesn't exist"
        else:
            '''Returned if execption was thrown because of another reason other than file being a symbolic link'''
            if len(e) <=32:
                return e
            else:
                return e[:32]

'''This functions returns the age in day of files'''
def file_age(file):
    '''Get age in epoch time of file'''
    return ((time.time()-os.stat(file).st_mtime)/86400)

'''Updates the db to yes for a given file.'''
def update_file_status(file,session):
    file_id = check_if_file_exists(file,session)
    update_file = session.query(FileHashes).get(file_id)
    update_file.updated = 'Yes'
    session.commit()

'''Bulk updates all rows to no in the updated column'''
def update_to_No(session):
    cur = session.query(FileHashes)
    cur.update({FileHashes.updated:'No'}, synchronize_session = False)
    session.commit()
    

'''retrieves hashes stored in the db.'''
def get_hash_from_db(file,session):
    file_id = check_if_file_exists(file,session)
    return session.query(FileHashes.file_hash).filter(FileHashes.file_id==file_id).scalar()

'''This method takes a file path and traverses it, computing files hashes of the files it discovers and inserts them to the database using the session'''
def walk_hash(file_path,session,hash=False):
    for root, dirs, files in os.walk(file_path,topdown=True):
        for name in files:
            discovered_file = os.path.join(root,name)
            '''Use try catch incase a file doesn't exist or you don't have permission or encounter other file exception'''
            try:
                if check_if_file_exists(discovered_file,session):
                    if hash:
                        '''If a hash has been stored then compare and only update if hash has changed. If no hash exists, update file status'''
                        if file_age(discovered_file) < 1 and (get_hash_from_db(discovered_file,session) == None):
                            update_file_status(discovered_file,session)
                        elif file_age(discovered_file) < 1 and (get_hash_from_db(discovered_file,session) != hash_file(discovered_file)):
                            update_file_status(discovered_file,session)
                    else:
                        if file_age(discovered_file) < 1 :
                            update_file_status(discovered_file,session)
                else:
                    if hash:
                        insert_hashes(discovered_file,hash_file(discovered_file),'Yes',session)
                    else:
                        insert_nonhashed(discovered_file,'Yes',session)
            except Exception as e:
                ''''Ideally add a logging mechanism to capture exception'''
                pass
            #print("file name : "+discovered_file+"\t file_hash : "+str(hash_file(discovered_file)))

'''Returns ta servers id. This value is inserted in the file hashes table to be used for joins.'''
def get_server_id(session):
    return session.query(BwServers.server_id).filter(BwServers.server_hostname==socket.gethostname()).scalar()

'''This method return the hostname and ip
    -----Will be modified later to take in an ip,a username and password/key file to allow it to get details for remote hosts'''
def get_Host_name_IP():
    try:
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        return host_name, host_ip
    except:
        print("Unable to get Hostname and IP")

'''This function checks if a file exists. It returns a file_id if it exists and None otherwise'''
def check_if_file_exists(file,session):
    '''Use try catch incase you don't you encounter file exception such as perimssion or non-existence'''
    try:
        return session.query(FileHashes.file_id).filter(FileHashes.file_name==file).scalar()
    except Exception as e:
        '''Write exception to log'''
        pass

'''This method takes a file name and its associated hash then adds it to the db. 
    -------Update the function to only take the file and then compute the hash and insert to db'''
def insert_hashes(file,hash,updated,session):
    add_files = FileHashes(file_name=file, file_hash=hash, updated=updated)
    session.add(add_files)
    session.commit()

'''This method inserts file name and updated status to File_Hashes table'''
def insert_nonhashed(file,updated,session):
    add_files = FileHashes(file_name=file, updated=updated)
    session.add(add_files)
    session.commit()
    

'''This function checks if a host exists. It returns a server_id if it exists.'''
def check_host_exits(session,hostname):
    return session.query(BwServers.server_id).filter(BwServers.server_hostname==hostname).scalar()
    
'''This method inserts servers if they don't exist'''    
def insert_servers(session):
    server_name, bwserver_ip = get_Host_name_IP()
    if check_host_exits(session,server_name):
        pass
    else:
        add_servers = BwServers(server_ip=bwserver_ip, server_hostname=server_name)
        session.add(add_servers)
        session.commit()

'''This method returns a cursor of the updated files.
    ---update to return servername'''
def get_updated_files(session):
    return session.query(FileHashes.file_name).filter(FileHashes.updated=='Yes')

'''This writes out a csv file of the files that have been updated.'''
def write_updated_to_file(session):
    file = socket.gethostname()+""+datetime.now().strftime("%Y%m%d")+".csv"
    f = open(file,'a+')
    for record in get_updated_files(session):
        f.write(get_service_name(record.file_name,6)+","+record.file_hash+"\n")

def write_updated_to_msg(session):
    file = socket.gethostname()+""+datetime.now().strftime("%Y%m%d")+".csv"
    msg= '\nApplication    |File name\n'
    for record in get_updated_files(session):
        rec = list(record)
        msg = msg + "{:<15}".format(get_service_name(record.file_name,6))+"|"+record.file_name+"\n"
        #msg = msg + record.file_name + "\n"
    return msg

'''This path takes in the file_name and returns the tibco service'''
def get_service_name(file,position=5):
    #/home/machua/python/APIs/RESTAPIs/ . The default is 5
    apps = file.split('/')
    return apps[position]

'''Updated traverse_finding_updating commenting the send email functionality'''
def traverse_finding_updated(smtp_port,base='/tibco/app/tibco/tra/domain/TIBCO_FS_DR/datafiles/',host=False):
    session = loadSession()
    insert_servers(session)
    walk_hash(base,session)
    sending_emails(write_updated_to_msg(session),smtp_port)
    update_to_No(session)

'''This create a ssh connection object used to create ssh connections
  --- You need to define a timeout incase a host is unreachable'''
#def traverse_remote(host,username,password,port=22,base_t=False):
#    ssh = paramiko.SSHClient()
#    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#    ssh.connect(host, port, username, password)
#    if not base_t:
#        stdin, home, stderr = ssh.exec_command('pwd')
#        stdin, stdout, stderr = ssh.exec_command(traverse_finding_updated(1025))
#    else:
#        stdin, stdout, stderr = ssh.exec_command(traverse_finding_updated(1025))

def traverse_remote(host,username,password,port=22,base_t='/tibco/app/tibco/tra/domain/TIBCO_FS_DR/datafiles/'):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port, username, password)
    
    stdin, stdout, stderr = ssh.exec_command(traverse_finding_updated(1025))


'''This function is used to send emails. It uses python's smtplib and email libraries'''
def sending_emails(message,port):
    app_changed = datetime.now().strftime("%Y/%m/%d")
    msg = EmailMessage()
    msg.set_content(message)
    msg['Subject'] = f'Changed Apps and Files as at  {app_changed}'
    msg['From'] = 'sender@localhost.com'
    msg['To'] = 'receiver@localhost.com'
    
    # Send the message via our own SMTP server.
    server = smtplib.SMTP('localhost',port)
    server.send_message(msg)
    server.quit()

'''This create a ssh connection object used to create ssh connections'''
def connect_remote_host(host,port,username,password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port, username, password)
    return ssh

if __name__ =="__main__":
    traverse_finding_updated(1025)
    traverse_remote('10.14.13.11','user','userpass!&*#',22,'/tibco/app/tibco/tra/domain/TIBCO_FS_DR/datafiles/')

    # For remote hosts
    # command = walk_hash('/home/machua',session)
    # ssh = paramiko.SSHClient()
    # ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # ssh.connect('10.81.26.203',22,'machua','MyPass')
    # stdin, stdout, stderr = ssh.exec_command(insert_servers(session))
    # stdin, stdout, stderr = ssh.exec_command(command)

    ### For printng errors in remote connection
    # lines = stdout.readlines()
    # print('********************About to print output*************************')
    # print(lines)
    # lines = stderr.readlines()
    # print('********************About to print error msgs*************************')
    # print(lines)

    ''''Updating a bunch of stuff to test branching feature of git.'''
