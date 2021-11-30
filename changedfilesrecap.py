from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
import os,socket

engine = create_engine('sqlite:///changedfilesrecap.db')
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

class FileAge(Base):
    __tablename__ = 'fileage'

    file_id = Column(Integer, primary_key=True)
    file_name = Column(String(100))
    file_path = Column(String(256))
    server_id = Column(Integer)

    def __repr__(self):
        return '''<FileAge(file_name{0},file_path{1})>'''.format(self.file_name,self.file_path)


Base.metadata.create_all(engine)

'''This method takes a file path and traverses it, computing files hashes of the files it discovers and inserts them to the database using the session'''
def walk_hash(file_path):
    for root, dirs, files in os.walk(file_path,topdown=True):
        for name in files:
            discovered_file = os.path.join(root,name)
            print("file name : "+discovered_file)

def get_hostname():
    return socket.gethostname

def get_Host_name_IP():
    try:
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        return host_name, host_ip
    except:
        print("Unable to get Hostname and IP")

def get_ip(hostname=''):
    if hostname:
        host_ip = socket.gethostbyname(hostname)
    else:
        host_ip = socket.gethostbyname('localhost')
    return  host_ip

if __name__ == "__main__":
    walk_hash('/home/machua/python')
