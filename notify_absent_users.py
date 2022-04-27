import logging, os, sys, time, warnings, smtplib, errno
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from configparser import SafeConfigParser
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import tableauserverclient as TSC

CONFIGURATION_FILE = ".\\config.txt"
LOG_FILE_NAME = 'notify_absent_users.log'

SCRIPT_FILE = os.path.basename(__file__).split('.')[0]
MAIN_LOGGER = logging.getLogger(SCRIPT_FILE)

def make_directories(path):
    
    try:
        directory = os.path.dirname(path)
        os.makedirs(directory)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise

def setup_logging(logger_name, log_file_dir, console_logging_level):

    # Make sure we have a place to write the logs
    make_directories(log_file_dir)

    # Determine log file name
    log_file_name = os.path.join(log_file_dir, LOG_FILE_NAME)

    # Create file handler
    fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh = RotatingFileHandler(log_file_name, maxBytes=8000000, backupCount=10)  # roll at ~8MB
    fh.setFormatter(fh_formatter)
    fh.setLevel(logging.DEBUG)

    # Create console handler
    ch_formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    # ch_formatter = logging.Formatter('# %(asctime)s - %(levelname)s - %(message)s')
    ch = logging.StreamHandler()
    ch.setFormatter(ch_formatter)
    ch.setLevel(console_logging_level)

    MAIN_LOGGER = logging.getLogger(logger_name)
    MAIN_LOGGER.setLevel(console_logging_level)
    MAIN_LOGGER.addHandler(fh);
    MAIN_LOGGER.addHandler(ch);

    MAIN_LOGGER.info(
        f'Console Logging Level is set to {console_logging_level}. Log File Logging Level is always set to DEBUG')

def send_email(message, to_address, config):
    
    msg = MIMEMultipart()
    msg.attach(MIMEText(message, 'html'))
    msg['To']      = to_address
    msg['From']    = config['notification']['from']
    msg['Subject'] = config['notification']['subject']
    
    smtp_server = smtplib.SMTP(config['smtp']['server'], config['smtp']['port'])
    
    if config['smtp']['do_tls']:
        smtp_server.starttls()
    
    if config['smtp']['username'] != None and config['smtp']['username'] != "":
        smtp_server.login(config['smtp']['username'], config['smtp']['password'])
    
    smtp_server.sendmail(config['notification']['from'], to_address, msg.as_string())
    smtp_server.quit()

def main():
    # Suppress SSL warnings
    warnings.simplefilter("ignore")
    execution_start_time = time.time()    

    #
    # Process config file
    #
    try:
        if not os.path.isfile(CONFIGURATION_FILE):
            raise Exception("{} not found".format(CONFIGURATION_FILE))
        
        fileconfigs = SafeConfigParser()
        fileconfigs.read(CONFIGURATION_FILE)
        config = {}   
        for section in fileconfigs.sections():        
            config[section] = {}
            
            for option in fileconfigs.options(section):
                
                if fileconfigs.get(section, option).lower() in ("true", "false", "yes", "no", "on", "off"):
                    config[section][option] = fileconfigs.getboolean(section, option)
                else:    
                    config[section][option] = fileconfigs.get(section, option)    

        # Convert delimited site string to a list
        if not config['server']['site_list'] == "":
            config['server']['site_list'] = config['server']['site_list'].replace(";", ",")
            config['server']['site_list'] = config['server']['site_list'].replace(" ", "")
            config['server']['site_list'] = config['server']['site_list'].split(",")
            # Convert to lower case for later comparisons
            config['server']['site_list'] = [x.lower() for x in config['server']['site_list']]

    except Exception as e:
        print("Config file processing failed: " + str(e))
        sys.exit(0)

    #
    # Setup logging
    #
    if not config['logging']['console_logging_level'] == "":
        console_logging_level = "INFO"
    else:
        console_logging_level = config['logging']['console_logging_level'].upper()

    setup_logging(SCRIPT_FILE, config['logging']['log_file_dir'], console_logging_level)
    
    MAIN_LOGGER.info(f"# Beginning {SCRIPT_FILE} execution #")

    # If we're testing, highlight this in log output
    if config['testing']['suppress_notification']:
        MAIN_LOGGER.info("")
        MAIN_LOGGER.info(f"  ** TEST MODE: Suppressing user notificatiions **")
        MAIN_LOGGER.info("")
    elif not config['testing']['user_email_redirect_to'] == "":
        MAIN_LOGGER.info("")
        MAIN_LOGGER.info(f"  ** TEST MODE: Redirecting user notifications to {config['testing']['user_email_redirect_to']} **")
        MAIN_LOGGER.info("")

    #
    # Setup server variables that will be shared by all interactions
    #
    tableau_auth = TSC.PersonalAccessTokenAuth(config['server']['personal_access_token_name'], 
                                               config['server']['personal_access_token_secret'])
    
    tableau_server = TSC.Server(config['server']['server_url'])
    tableau_server.add_http_options({'verify': False})

    # This is the first call to the server, giving us a handy API connectivity check
    try:
        tableau_server.use_server_version()
    except Exception as e:
        MAIN_LOGGER.error(f"Server connectivity failed. Verify URL {config['server']['server_url']}")
        raise e

    #
    # Gather target sites
    #
    target_site_items = []

    MAIN_LOGGER.info(f"  Logging into {config['server']['server_url']} (default site)")
    with tableau_server.auth.sign_in(tableau_auth):

        MAIN_LOGGER.info("  Getting target site list")
        all_site_items = list(TSC.Pager(tableau_server.sites))
        MAIN_LOGGER.info(f"    Found {len(all_site_items)} total sites")

    for site_item in all_site_items:
        if (
            site_item.state == TSC.SiteItem.State.Active and 
                (
                config['server']['site_list'] == "" or
                site_item.content_url.lower() in config['server']['site_list'] or
                site_item.name.lower() in config['server']['site_list']
                )
        ):
            target_site_items.append(site_item)
    MAIN_LOGGER.info(f"    Targeting {len(target_site_items)} active site(s)")

    #
    # Find absent users on each site
    #

    MAIN_LOGGER.info(f"  Searching {len(target_site_items)} site(s) for users who haven't logged in for {config['users']['last_login_threshold_days']} days")
    total_site_users_notified = 0
    
    for site_item_index, site_item in enumerate(target_site_items, start=1):
        MAIN_LOGGER.info(f"  Site {site_item_index} of {len(target_site_items)}: {site_item.name}")
        tableau_auth.site_id = site_item.content_url
        
        with tableau_server.auth.sign_in(tableau_auth):
        
            site_user_items = list(TSC.Pager(tableau_server.users))
        
            for user_item in site_user_items:
        
                #TODO: Continue if user was created within the threshold time period
                # That requires getting the created_at data from the DB
                # For now, ignore users that have never logged in.
                if user_item.last_login is None:
                    continue

                # If the user's last login is older than our threshold, send the notification.
                days_since_last_login = (datetime.now(timezone.utc)-user_item.last_login).days
                
                if days_since_last_login >= int(config['users']['last_login_threshold_days']):
                    reason_short = f"Last login {days_since_last_login} days ago"
                    reason_long  = f"you haven't logged into Tableau site '{site_item.name}' in {days_since_last_login} days"
                
                    MAIN_LOGGER.info(f"    User '{user_item.name}': {reason_short}")
                    
                    if not user_item.email:
                        MAIN_LOGGER.info("      Email missing for user")
                        continue
                    else:
                        MAIN_LOGGER.info(f"      Sending notification to {user_item.email}")

                        if config['testing']['suppress_notification']:
                            continue
                        
                        # Setup email
                        body_text = []

                        body_text.append(f"{user_item.fullname}, <p>")
                        body_text.append(config['notification']['body_notification_reason'].format(reason_text=reason_long))
                        body_text.append("<p>")
                        body_text.append(config['notification']['body_helpful_information'])
                            
                        if not config['testing']['user_email_redirect_to'] == "":
                            email_to = config['testing']['user_email_redirect_to']
                        else:
                            email_to = user_item.email
                        
                        send_email("".join(body_text),
                                   email_to,
                                   config)

                    total_site_users_notified += 1
                              
    MAIN_LOGGER.info(f"  Notified {total_site_users_notified} site-users")

    execution_end_time   = time.time()
    execution_total_time = execution_end_time - execution_start_time
    mins, secs = divmod(execution_total_time, 60)
    hours, mins = divmod(mins, 60)
    MAIN_LOGGER.info(f"Total running time: {int(hours)}:{int(mins)}:{int(secs)}")    
    MAIN_LOGGER.info(f"# Ending {SCRIPT_FILE} execution #")   

if __name__ == "__main__":
    main()