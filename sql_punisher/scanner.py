from argparse import ArgumentParser;
from src.system_conf import ERRORS_LIST, CHARS_LIST;

from pprint import pprint;
from colorama import Fore;
from src.banner import PUNISHER_TEXT, SQL_TEXT, BANNER;

from urllib.parse import urljoin;

from requests import Session;
from bs4 import BeautifulSoup as BSoup;



class SQL:
    def __init__(
        self, target):

        self.target = target;
        self.session = Session();
    

    def show_banner(
        self, banner,
        text_list):        
        print(
            Fore.LIGHTRED_EX + banner);
        print(
            Fore.YELLOW + text_list[0]);
        print(
            Fore.YELLOW + text_list[1]);


    def init_soup(
        self, session,
        headers, target, 
        ptype):

        session.headers["User_Agent"] = headers;

        return BSoup(
            session.get(
            target).content,
            ptype);


    def get_all_forms(
        self, soup):
        return soup.find_all(
            "form");


    def get_details(
        self, form):
        
        details = {

        };

        try:
            action = form.attrs.get(
                'action').lower();

        except: 
            action = None;

        method = form.attrs.get(
            'method',
            'get').lower();

        inputs = [

        ];

        for tag in form.find_all('input'):
            type = tag.attrs.get(
                'type',
                'text');

            name = tag.attrs.get(
                'name');

            value = tag.attrs.get(
                'value',
                '');

            inputs.append(
                {
                    "type": type,
                    "name": name,
                    "value": value,
                });

        details["action"] = action;
        details["method"] = method;
        details["inputs"] = inputs;

        del action, method, inputs;
        return details;


    def is_vulnerable(
        self, errors,
        response):

        for error in errors:
            if (error in response.content.decode().lower()):
                return True;
    
        return False;


    def scan(
        self, session,
        chars, errors,
        soup, target):

        self.show_banner(
            BANNER,
            [
            SQL_TEXT,
            PUNISHER_TEXT,
            ]);

        for char in chars:
            targetU = f"{target}{char}";

            print(
                f"\n{Fore.LIGHTBLUE_EX}[*] Trying : {Fore.WHITE}'{Fore.CYAN + targetU}{Fore.WHITE}'");

            response = session.get(
                targetU);

            if (self.is_vulnerable(
                errors,
                response)):
                print(
                    f"{Fore.LIGHTBLUE_EX}[!] SQL Injection Vulnerability Detected on : {Fore.WHITE}'{Fore.CYAN + targetU}{Fore.WHITE}'");

            del targetU, response, char; 


        forms = self.get_all_forms(
            soup);

        print(
            f"\n{Fore.GREEN}[*] Detected {len(forms)} forms on {target}");

        for form in forms:
            details = self.get_details(
                form);

            for char in chars:
                data = {

                };

                inputs = details["inputs"]

                for input in inputs:
                    if (input["type"] == "hidden"
                        or input["value"]):
                        try:
                            data[input["name"]] = input["value"] + char;

                        except:
                            pass;

                    elif (input["type"] != "submit"):
                        data[input["name"]] = f"test{char}";

                targetU = urljoin(
                    target, 
                    details["action"]);

                if (details["method"] == "post"):
                    response = session.post(
                        targetU,
                        data=data);

                elif (details["method"] == "get"):
                    response = session.get(
                        targetU,
                        params=data);

                if (self.is_vulnerable(
                        errors,
                        response)):
                    print(
                    f"{Fore.LIGHTBLUE_EX}[!] SQL Injection Vulnerability Detected on : {Fore.WHITE}'{Fore.CYAN + targetU}{Fore.WHITE}'");
                    
                    print(
                        "[*] Form details:");
                    pprint(details);

                _isVul_ = True;
                break;
                                
            del data, input, inputs, response, details, char;

            if (_isVul_):
                print(
                    f"\n{Fore.RED}[!] SQL Injection Vulnerability Discovered on : {targetU}");

            else: 
                print(
                    f"{Fore.GREEN}[+] This site is secure!");


def argument_parser():
    parser = ArgumentParser(
        prog='scanner.py',
        epilog='You have to set target, to start punishing the NET.');

    parser.add_argument(
        '-t', '--target',
        help='set target (web-site, web-application)');
    parser.add_argument(
        '-v', '--verbose');

    return parser.parse_args();


def main():
    args = argument_parser();
    
    exec_ = SQL(
        args.target);
    
    soup = exec_.init_soup(
        exec_.session,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0",
        exec_.target,
        'html.parser');

    exec_.scan(
        exec_.session,
        CHARS_LIST,
        ERRORS_LIST,
        soup,
        exec_.target);

    print(Fore.RESET + "\r");


if __name__ == "__main__":
    main();
