import io
import time


class Transaction:
    def __init__(self, raw=None):
        if raw != None:
            try:
                self.sender = raw.split("->")[0].strip()
                self.receiver = raw.split("->")[1].split(":")[0].strip()
                self.amount = float(raw.split(":")[1].split(",")[0].strip())
                self.message = "".join(raw.split(",")[1:]).strip()
            except:
                self.sender = ""
                self.receiver = ""
                self.amount = 0.00
                self.message = f"Error while parsing transaction: {raw}! Please contact our support at <insert contact info here>!"

        else:
            self.sender = ""
            self.receiver = ""
            self.amount = 0.00
            self.message = ""

    def formatted(self, without_newline=False):
        return f'{self.sender} -> {self.receiver}: {self.amount:0.2f}, {self.message}' + ("\n" if not without_newline else "")

    def __str__(self):
        return f"Transaction of {self.amount:0.2f} from {self.receiver} to {self.sender}: {self.message}"

    def __repr__(self):
        return str(self)


class UserAccount:
    def __init__(self, account_id: str):
        self.id = account_id
        self.reader = BlockReader(account_id)
        self.balance = self.reader.get_balance()
        self.transactions = self.reader.get_transactions()
        self.password = self.reader.get_password()
        self.recovery_phrase = self.reader.get_recovery()


    def update_balance(self, new_bal: float):
        self.reader.update_balance(new_bal)

    def update_recovery(self, new_recovery: str):
        self.reader.update_recovery(new_recovery)
        self.recovery_phrase = new_recovery

    def update_password(self, new_pass: str):
        self.reader.update_password(new_pass)
        self.password = new_pass

    def add_transaction(self, transaction: Transaction):
        self.transactions.append(transaction)
        self.reader.add_transaction(transaction)

    def refresh_balance(self):
        self.reader.refresh_lines()
        self.balance = self.reader.get_balance()

    def refresh_password(self):
        self.reader.refresh_lines()
        self.password = self.reader.get_password()

    def refresh_transactions(self):
        self.reader.refresh_lines()
        self.transactions = self.reader.get_transactions()

    def refresh_recovery(self):
        self.reader.refresh_lines()
        self.recovery_phrase = self.reader.get_recovery()

    def refresh(self):
        self.reader.refresh_lines()
        self.refresh_balance()
        self.refresh_password()
        self.refresh_transactions()



class Logger:
    def __init__(self):
        self.current_chunk = time.localtime().tm_min // 5
        self.file = io.open(f"./logs/{self.current_chunk}.log", "a")
        self.file.truncate()
        self.check_switch_log()


    def log_transaction(self, t: Transaction):
        self.file.write(f"[{time.asctime()}] User {t.sender} send {t.amount} to {t.receiver}: {t.message}\n")
        self.file.flush()
        self.check_switch_log()


    def log(self, msg: str):
        self.file.write(f"[{time.asctime()}] {msg}" + '\n' if msg[-1] != '\n' else '')
        self.file.flush()
        self.check_switch_log()


    def check_switch_log(self):
        chunk = time.localtime().tm_min // 5

        if chunk != self.current_chunk:
            self.current_chunk = chunk
            self.file.close()
            self.file = io.open(f"./logs/{chunk}.log", "a")


class BlockReader():
    def __init__(self, account_id: int):
        self.id = account_id
        self.file = io.open(f"accounts/{account_id}", "r+")
        self.lines = self.file.readlines()

    def refresh_lines(self):
        self.file.seek(0)
        self.lines = self.file.readlines()

    def update_balance(self, new_bal: float):
        self.lines[4] = f"{new_bal:0.2f}\n"
        self.write_changes()

    def update_password(self, new_pass: str):
        self.lines[1] = new_pass + "\n"
        self.write_changes()

    def update_recovery(self, new_value: str):
        self.lines[7] = new_value + "\n"
        self.write_changes()

    def add_transaction(self, transaction: Transaction):
        self.lines.append(transaction.formatted())
        self.write_changes()

    def get_balance(self) -> float:
        return float(self.lines[4].strip())

    def get_password(self) -> str:
        return self.lines[1].strip()

    def get_transactions(self) -> list[Transaction]:
        self.refresh_lines()
        res = list()
        for line in self.lines[10:]:
            if not line.strip():
                break

            res.append(Transaction(line))
            
        return res

    def get_recovery(self) -> str:
        return self.lines[7].strip()

    def write_changes(self):
        self.file.seek(0)
        self.file.writelines(self.lines)
        self.file.truncate()
        self.file.flush()


    def __str__(self):
        return f"Reader for {self.id}({self.file}) | \n{''.join(self.lines)}"
