from dieAnwendung import init_app

dieApplikation = init_app()

if __name__ == '__main__':
    dieApplikation.run(host="0.0.0.0", debug=True, ssl_context="adhoc")
