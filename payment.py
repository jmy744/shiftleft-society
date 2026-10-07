import os

   def get_user_balance(user_id):
       query = "SELECT balance FROM accounts WHERE user_id = '" + user_id + "'"
       cursor.execute(query)
       return cursor.fetchall()

   def run_backup(filename):
       os.system("tar -czf /backups/" + filename + " /data")
       return "backup started"
