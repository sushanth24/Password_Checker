# importing packages
import requests
import hashlib
import sys

# setting the required api data and url and getting the response
def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f"Error fetching: {res.status_code}, check the api and try again"
        )
    return res


# checking the match to the password with the tail in the response and returning correct count
def get_password_leaks_count(hashes, hash_to_check):
    # splitting the response into two parts and making the tuple
    hashes = (line.split(":") for line in hashes.text.splitlines())
    # iterating through the tuple to get count and matched passwords to check the match with tail
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# hashing the password and passing required first five numbers of hashed passwords and getting the response
def pwned_api_check(password):
    # hashing the password and setting the digits to hex and to upper case letters
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


# getting the password from user input and passing to the api_check function to get the count and printing the output
def main(password):
    password = input("Enter the password you want to check: ")
    count = pwned_api_check(password)
    if count:
        print(
            f"{password} was found {count} times... you should probably change your password!"
        )
    else:
        print(f"{password} was NOT found. Carry on!")
    return "done!"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
