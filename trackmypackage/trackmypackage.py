import configparser
import logging
import smtplib
from email.message import EmailMessage
import requests

def getRequestExceptionString(url, data):
    return f"An exception occurred during request to URL:\n{url}\nWith request data:\n{data}\n"

def getCfgFileParams(file_name, section, cfg_params):
    cfg_values = []
    try:
        config_parser = configparser.RawConfigParser()
        config_filepath = file_name
        config_parser.read(config_filepath)

        for cfg_param in cfg_params:
            cfg_values.append(config_parser.get(section, cfg_param))

        return tuple(cfg_values)
    except Exception as e:
        logging.exception(f"Error reading file {file_name}")
        return "", "", ""

def StillSameOccurrence(p_last_occurreance_code):
    try:
        with open("lastoccurrencedetails.txt", "r") as lastoccurrencedetails_file:
            return lastoccurrencedetails_file.read().split(";")[0] == str(p_last_occurreance_code)
    except FileNotFoundError:
        return False
    
def WriteLastOccurrenceDetails(p_last_occurrence_details):
    code = p_last_occurrence_details.codigo
    occurrence_code = p_last_occurrence_details.codigo_ocorrencia
    occurrence = p_last_occurrence_details.ocorrencia
    obs = p_last_occurrence_details.obs
    occurrence_date = p_last_occurrence_details.data_ocorrencia
    occurrence_dt_registered = p_last_occurrence_details.data_cadastro
    occurrence_dt_utc = p_last_occurrence_details.data_ocorrencia_dt

    with open("lastoccurrencedetails.txt", "w") as lastoccurrencedetails_file:
        lastoccurrencedetails_file.write(f"{code};{occurrence_code};{occurrence};{obs};{occurrence_date};{occurrence_dt_registered};{occurrence_dt_utc}")


def logResponseData(p_response_data):
    general_info = p_response_data[0][0]
    shipping_details = p_response_data[1]

    #*********** GENERAL INFO *********** 
    destinatario = general_info.destinatario
    remetente = general_info.remetente
    servico = general_info.servico
    ultima_ocorrencia = general_info.ultima_ocorrencia
    situacao = general_info.situacao

    #Shipping company info
    empresa = general_info.empresa
    contato_empresa = general_info.contato_empresa
    email_empresa = general_info.email_empresa
    fornecedor_email = general_info.fornecedor_email
    fornecedor_telefone1 = general_info.fornecedor_telefone1

    #Who received
    recebedor = general_info.recebedor
    recebedor_documento = general_info.recebedor_documento
    recebedor_parentesco = general_info.recebedor_parentesco

    #*********** SHIPPING DETAILS ***********
    if not StillSameOccurrence(shipping_details[0].codigo):
        WriteLastOccurrenceDetails(shipping_details[0])
        #for occurrence in shipping_details:
    else:
        logging.info(f"No updates on the shipping details. Last Occurrence: {shipping_details[0].ocorrencia}; Date: {shipping_details[0].data_ocorrencia}")

logging.basicConfig(
    filename='trackmypackage.log',
    filemode='a',
    format='[%(levelname)s] %(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.DEBUG
)

url_param, codigo, cpf_cnpj, g_recaptcha_response = getCfgFileParams(r'requestparams.cfg', 'REQUEST', ['codigo', 'cpf_cnpj', 'g-recaptcha-response'])

payload = {'codigo':codigo, 'cpf_cnpj':cpf_cnpj, 'g-recaptcha-response':g_recaptcha_response}

request_url = f"https://www.englobasistemas.com.br/gestao/api/PesquisasExternas/PesquisarPedidosCnpjCpf?{url_param}"

try:
    logging.info(f"Making request to URL {request_url}")
    response_data = requests.post(request_url, data=payload)
    logResponseData(response_data)
except Exception as e:
    logging.exception(getRequestExceptionString(request_url, payload))