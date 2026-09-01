from __future__ import annotations

import datetime
import hashlib
import os
import unittest
from unittest import mock


os.environ.setdefault("DB_URI", "sqlite:////tmp/marscasino-hardening-tests.db")

import app as service  # noqa: E402  (DB_URI must be selected before import)


class MarscasinoHardeningTests(unittest.TestCase):
    def setUp(self):
        service.app.config["TESTING"] = True
        with service.app.app_context():
            service.db.drop_all()
            service.db.create_all()
        self.client = service.app.test_client()

    def _user(self, username, *, password="password", session="", coins=10,
              fcode=None):
        user = service.UserModel(
            username=username,
            password=password,
            ip="::1",
            code=username + "-code",
            created=datetime.datetime.now(),
            session=session,
            active=True,
            coins=coins,
            recruited_by="",
            fcode=fcode or (username + "0" * 32)[:32],
        )
        with service.app.app_context():
            service.db.session.add(user)
            service.db.session.commit()

    def _login_cookie(self, session):
        self.client.set_cookie("localhost", "session", session)

    def _register(self, username, fcode=""):
        with mock.patch.object(service.socket, "socket", side_effect=OSError):
            response = self.client.post("/register", data={
                "username": username,
                "password": "password",
                "ip": "::1",
                "fcode": fcode,
            })
        self.assertEqual(response.status_code, 200)

    def test_zero_bet_only_wins_when_zero_is_drawn(self):
        self._user("roulette-loss", session="loss-session")
        self._login_cookie("loss-session")
        with mock.patch.object(service.random, "randint", return_value=7):
            response = self.client.post("/game1", data={"bet": "1", "field": "0"})
        self.assertIn(b"The number was 7 and you win 0 coins", response.data)
        with service.app.app_context():
            self.assertEqual(service.UserModel.query.get("roulette-loss").coins, 9)

        self._user("roulette-win", session="win-session")
        self._login_cookie("win-session")
        with mock.patch.object(service.random, "randint", return_value=0):
            response = self.client.post("/game1", data={"bet": "1", "field": "0"})
        self.assertIn(b"The number was 0 and you win 36 coins", response.data)
        with service.app.app_context():
            self.assertEqual(service.UserModel.query.get("roulette-win").coins, 45)

    def test_third_column_and_number_36_are_playable(self):
        self._user("roulette-third", session="third-session")
        self._login_cookie("third-session")
        with mock.patch.object(service.random, "randint", return_value=3):
            response = self.client.post(
                "/game1", data={"bet": "1", "field": "third"})
        self.assertIn(b"The number was 3 and you win 2 coins", response.data)
        with service.app.app_context():
            self.assertEqual(service.UserModel.query.get("roulette-third").coins, 11)

        self._user("roulette-36", session="number-session")
        self._login_cookie("number-session")
        with mock.patch.object(service.random, "randint", return_value=36):
            response = self.client.post(
                "/game1", data={"bet": "1", "field": "36"})
        self.assertIn(b"The number was 36 and you win 35 coins", response.data)
        with service.app.app_context():
            self.assertEqual(service.UserModel.query.get("roulette-36").coins, 44)

    def test_referral_limit_survives_recruited_account_deletion(self):
        recruiter_code = "R" * 32
        self._user("recruiter", fcode=recruiter_code)

        for index in range(4):
            username = "recruit%02d" % index
            self._register(username, recruiter_code)
            with service.app.app_context():
                recruit = service.UserModel.query.get(username)
                self.assertNotEqual(
                    recruit.fcode,
                    hashlib.md5(username.encode()).hexdigest(),
                )
                recruit.active = True
                recruit.session = "session-%02d" % index
                service.db.session.commit()

            self._login_cookie("session-%02d" % index)
            response = self.client.post("/delete-account", data={
                "username": username,
                "password": "password",
            })
            self.assertEqual(response.status_code, 302)

        with service.app.app_context():
            recruiter = service.UserModel.query.get("recruiter")
            self.assertEqual(recruiter.coins, 160)
            self.assertEqual(
                service.ReferralModel.query.filter_by(
                    recruiter_code=recruiter_code).count(),
                3,
            )

    def test_delete_cannot_select_another_account_from_post_body(self):
        self._user("attacker", session="attacker-session")
        self._user("victim", password="victim-password")
        self._login_cookie("attacker-session")

        response = self.client.post("/delete-account", data={
            "username": "victim",
            "password": "victim-password",
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Wrong password", response.data)
        with service.app.app_context():
            self.assertIsNotNone(service.UserModel.query.get("victim"))


if __name__ == "__main__":
    unittest.main()
