from util import Transaction, UserAccount, BlockReader, Logger
from base64 import b64encode, b64decode
import string
import random
import os
import io


BANNER = r"""
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 ____   _       ___     __  __  _      ____   ___   ____   ___ 
|    \ | |     /   \   /  ]|  |/ ]    |    \ /   \ |    \ /  _]
|  o  )| |    |     | /  / |  ' /     |  D  )     ||  o  )  [_ 
|     || |___ |  O  |/  /  |    \     |    /|  O  ||   _/    _]
|  O  ||     ||     /   \_ |     \    |    \|     ||  | |   [_ 
|     ||     ||     \     ||  .  |    |  .  \     ||  | |     |
|_____||_____| \___/ \____||__|\_|    |__|\_|\___/ |__| |_____|

+++++++++++++++++ Blockchain reinvisioned +++++++++++++++++++++
"""
#]]


CHARSET = list(set(string.whitespace) - set(" "))

MIN_RECOVERY_LENGTH = 8
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 256
MAX_ID_LEN = 16

WELCOME_BONUS = 10.00

LOGGER = Logger()



def start_screen():
    clear_screen()
    print(BANNER)

    while True:
        choice = input("Welcome, would you like to login, register or recover an existing account?\n> ").strip().lower()
        clear_screen()

        if choice.startswith("login"):
            login()

        elif choice.startswith("register"):
            register()

        elif choice.startswith("recover"):
            recover_account()

        elif choice == "exit":
            print(BANNER)
            print("Goodbye!")
            exit(69)

        else:
            print(BANNER)
            print()
            print("Unknown choice!")
            print()
            print("Available options are:")
            print("login        Log into your account")
            print("register     Create a new account")
            print("recover      Recover your account")
            print("exit         Exit")



def login():
    print(BANNER)
    user_id = input("Enter User ID: ").strip()
    password = input("Enter password: ")

    try:
        user = UserAccount(user_id)
        if b64encode(password.encode("latin-1")) != user.password.encode("latin-1"):
            clear_screen()
            print(BANNER)
            print("Incorrect password!")
            return

        LOGGER.log(f"User {user_id} logged in.")
        main_screen(user)


    except FileNotFoundError:
        print("User does not exist!")
        input()
        return



def main_screen(user: UserAccount):
    clear_screen()
    print(BANNER)
    print(f"Welcome user {user.id}!\n")
    while True:
        user.refresh()
        balance = user.balance
        print(f"Your balance: {balance:0.2f}")
        print("Recent Transactions:")
        transactions = user.transactions[-3:]
        print("\n".join(t.formatted(without_newline=True) for t in transactions) if transactions else "No transactions yet...")
        print()
        print("")
        com = input("> ").strip().lower()
        if com.startswith("help"):
            show_options()

        elif com.startswith("send"):
            r_id = ""
            while True:
                r_id = input("Receiver: ").strip()
                if not r_id:
                    main_screen(user)
                    return
                try:
                    receiver = UserAccount(r_id)
                    break
                except FileNotFoundError:
                    print("Account does not exist!")

            print()
            amount = float(input("Transaction amount: "))
            print()
            msg = filter_input(input("Transaction message (optional): ").strip())

            print()
            user.refresh()
            cur = user.balance
            if cur < amount:
                print("Insufficient balance!")
                continue

            t = Transaction()
            t.amount = amount
            t.sender = user.id
            t.receiver = receiver.id
            t.message = msg

            user.update_balance(cur - amount)
            user.add_transaction(t)
            receiver.refresh_balance()
            receiver.update_balance(receiver.balance + amount)
            receiver.add_transaction(t)
            
            LOGGER.log_transaction(t)
            clear_screen()
            print("Transaction successfully send!")
            print()
            print(BANNER)

        elif com.startswith("history"):
            user.refresh_transactions()
            print("Recent transactions: ")
            print("\n".join(t.formatted() for t in user.transactions[-20:]))

            input("<Press Enter to continue>")
            clear_screen()
            print(BANNER)

        elif com.startswith("logout"):
            return

        elif com.startswith("recover"):
            print("To change your recovery phrase, please enter your current password.")
            password = input("Current password: ")
            if b64encode(password.encode("latin-1")) != user.password.encode("latin-1"):
                print("Incorrect password!")
                continue

            print("Please enter your new recovery phrase:")
            while True:
                new_recovery = input("> ")

                if len(new_recovery) >= MIN_RECOVERY_LENGTH and is_valid_input(new_recovery):
                    break
                elif len(new_recovery) < MIN_RECOVERY_LENGTH:
                    print(f"Recovery phrase needs to be at least {MIN_RECOVERY_LENGTH} characters long!")
                else:
                    print("Recovery phrase contains illegal characters!")


            user.update_recovery(new_recovery)

            LOGGER.log(f"User {user.id} updated their recovery phrase!\n")
            clear_screen()
            print(BANNER)
            print("Recovery phrase updated successfully!")
            print()



def register():
    clear_screen()
    print(BANNER)

    print("Please enter a User ID or 'random' for a random id:")
    print()
    while True:
        print()
        try:
            id = input("User ID: ").strip()

            if not id:
                return

            if len(id) > MAX_ID_LEN:
                print(f"User ID can not exceed {MAX_ID_LEN} characters!")
                continue

            if id.startswith("random"):
                exists = set(os.listdir("accounts/"))
                id = random.randint(0, 10**MAX_ID_LEN)
                while id in exists:
                    id = random.randint(0, 10**MAX_ID_LEN)
                print(f"Your automatically generated User ID: {id}")

            id = int(id)
            if os.path.isfile(f"accounts/{id}"):
                print("User already exists!")
                continue

            p1 = input("Password: ")

            if len(p1) < MIN_PASSWORD_LENGTH:
                print(f"Password must have at least {MIN_PASSWORD_LENGTH} characters!")
                continue

            elif len(p1) > MAX_PASSWORD_LENGTH:
                print(f"Password must have at most {MAX_PASSWORD_LENGTH} characters!")
                continue
            
            p1 = b64encode(p1.encode("latin-1"))
            p2 = b64encode(input("Repeat password: ").encode("latin-1"))

            if p1 != p2:
                print("Passwords don't match! Please try again!")
                continue

            recovery = input("Recovery phrase: ")

            if not is_valid_input(recovery):
                print("Recovery phrase contains invalid characters!")
                continue

            elif len(recovery) < MIN_RECOVERY_LENGTH:
                print(f"Recovery phrase must have at least {MIN_RECOVERY_LENGTH} characters!")
                continue

            lines = ["Password:\n", p1.decode("latin-1")+"\n", "\n", "Balance:\n", f"{WELCOME_BONUS:0.2f}\n", "\n", "Recovery-Token:\n", recovery+"\n", "\n", "Transactions:\n"]

            #create user file
            f = io.open(f"accounts/{id}", "w")
            f.writelines(lines)
            f.close()

            user = UserAccount(id)
            t = Transaction()
            t.sender = "System"
            t.receiver = id
            t.amount = WELCOME_BONUS
            t.message = f"Your Welcome Bonus of {WELCOME_BONUS:0.2f}!"
            user.add_transaction(t)

            LOGGER.log(f"New user {user.id} signed up!\n")
            main_screen(user)
            return

        except ValueError:
            print("Invalid User ID!")
            continue

        except UnicodeDecodeError:
            print("Invalid input!")
            continue



def recover_account():
    clear_screen()
    print(BANNER)
    print("Please enter the account you want to recover:")
    try:
        id = int(input("> "))
    except ValueError:
        print("Invalid User ID, exiting!")
        return

    except FileNotFoundError:
        print("User was not found!")
        return

    phrase = ""
    while not phrase:
        print("Please enter the recovery phrase:")
        phrase = input("> ")

    user = UserAccount(id)
    if phrase != user.recovery_phrase:
        clear_screen()
        print(BANNER)
        print("Incorrect recovery phrase!")
        return

    # reset password
    print("Recovery phrase verified.")
    print()
    print("Please enter your new password:")

    while True:
        p1 = input("Password: ")

        if len(p1) < MIN_PASSWORD_LENGTH:
            print(f"Password must have at least {MIN_PASSWORD_LENGTH} characters!")
            continue

        elif len(p1) > MAX_PASSWORD_LENGTH:
            print(f"Password must have at most {MAX_PASSWORD_LENGTH} characters!")
            continue

        p1 = b64encode(p1.encode("latin-1"))
        p2 = b64encode(input("Repeat password: ").encode("latin-1"))

        if p1 != p2:
            print("Passwords don't match! Please try again!")
            continue

        break

    user.update_password(p1.decode("latin-1"))
    print("Password successfully changed!")



def filter_input(inp: str) -> str:
    return "".join(filter(lambda c: c not in CHARSET, inp))


def is_valid_input(inp: str) -> bool:
    return all(c not in CHARSET for c in inp)



def show_options():
    print("""
send        Send money
history     Show your transaction history
recovery    Update your recovery phrase
logout      Log out
help        Display this message
""")



def clear_screen():
    os.system("clear")


if __name__ == "__main__":
    try:
        start_screen()
    except:
        print("An error occured and this session is being terminated. Thank you for using Block Rope!")
        exit(1337)
