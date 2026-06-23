"""A few valid country names the service's IATA map accepts.

The handlers only need a couple of names to fill the flight-creation form;
the full table lives in the baked service image (image/service/.../iata.py).
"""

country_dict = {
    "Deutschland": "FRA",
    "Frankreich": "CDG",
    "Spanien": "MAD",
    "Italien": "FCO",
    "Japan": "HND",
}
