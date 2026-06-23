import time



while True:
    try:
        sleep_time = 60 * (4 - (time.localtime().tm_min % 5))
        print(f"sleeping for {sleep_time} seconds...")
        time.sleep(sleep_time)

        # clear next chunk
        next_chunk = ((time.localtime().tm_min // 5) + 1) % 12
        print(f"clearing chunk {next_chunk}...")

        log_banner = f"""
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
{'BlockRope System Log':^64}
{'Version:':^64}
{'1.1':^64}
{'Log file number:':^64}
{next_chunk:^64}
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

"""

        with open(f"./logs/{next_chunk}.log", "w") as f:
            f.write(log_banner)
            f.truncate()

        time.sleep(60)

    except Exception as e:
        with open("/tmp/blockrope_cleaner_errors.log", "a") as f:
            f.write(f"[{time.asctime()}] A {type(e).__name__} occured: {e}")
