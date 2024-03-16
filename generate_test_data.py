#!/usr/bin/env python3

from dataclasses import dataclass
from pathlib import Path
import random
import string
from typing import Sequence

## Generate random ascii strings
# Bruce Truong
# Generates 250 characters to support privacy encryption project

USERNAME_SIZE = 20
PASSWORD_SIZE = 20
MSG_SIZE = 250

def random_str(length) -> str:
# This contains a-z, A-Z, and spaces
  valid_chars = string.ascii_letters + ' '
# Generate a string of 250 characters from valid characters
  output = ''.join(random.choice(valid_chars) for _ in range(length))
  return output

## Generate usernames, passwords, and messages

class Serializeable:
  def ser(self) -> str: ...

def ser_list(l: Sequence[Serializeable]) -> str:
  l_ser = [x.ser() for x in l]
  return f'[{",".join(l_ser)}]'

def ser_list_pair_str(l: Sequence[tuple[str, str]]) -> str:
  l_ser = [f'["{x}","{y}"]' for x, y in l]
  return f'[{",".join(l_ser)}]'

def ser_list_str(l: Sequence[str]) -> str:
  l_ser = [f'"{x}"' for x in l]
  return f'[{",".join(l_ser)}]'

@dataclass
class User(Serializeable):
  username: str
  password: str

  def ser(self) -> str:
    return f'{{"username":"{self.username}","password":"{self.password}"}}'

@dataclass
class Message(Serializeable):
  from_user: str
  to_user: str
  message: str

  def ser(self) -> str:
    return  f'{{"from":"{self.from_user}","to":"{self.to_user}","message":"{self.message}"}}'

@dataclass
class TestData(Serializeable):
  users: list[User]
  messages: list[Message]

  def ser(self) -> str:
    s_users = ser_list(self.users)
    s_messages = ser_list(self.messages)
    return f'{{"users":{s_users},"messages":{s_messages}}}'

def gen_user() -> User:
  username = random_str(USERNAME_SIZE) 
  password = random_str(PASSWORD_SIZE)
  return User(username, password)

def gen_message(users: list[User]) -> Message:
  from_user = random.choice(users).username
  to_user = random.choice(users).username
  msg = random_str(MSG_SIZE)
  return Message(from_user, to_user, msg)

def gen_data(num_users: int, num_messages: int) -> TestData:
  users = [gen_user() for _ in range(num_users)]
  messages = [gen_message(users) for _ in range(num_messages)]
  return TestData(users, messages)

def main():

  output_path = Path("./resources/test/test_setup.json")
  test_data = gen_data(1000, 10000)
  output_path.parent.mkdir(parents=True, exist_ok=True)
  with open(output_path, 'w') as f:
    f.write(test_data.ser())

  output_path = Path("./resources/test/delete_users.json")
  num_delete_users = 100
  users_names = list(map(lambda u: u.username, test_data.users))
  random.shuffle(users_names)
  users = users_names[:num_delete_users]
  with open(output_path, 'w') as f:
    f.write(ser_list_str(users))

  output_path = Path("./resources/test/test_setup_2.json")
  test_data = gen_data(100, 10000)
  with open(output_path, 'w') as f:
    f.write(test_data.ser())

  output_path = Path("./resources/test/delete_chats.json")
  num_pairs = 100
  user_pairs = list(map(lambda m: (m.from_user, m.to_user), test_data.messages))
  random.shuffle(user_pairs)
  user_pairs = user_pairs[:num_pairs]
  with open(output_path, 'w') as f:
    f.write(ser_list_pair_str(user_pairs))

  print('Done')

if __name__ == "__main__":
  main()

