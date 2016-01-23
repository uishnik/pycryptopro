# coding: utf-8

from subprocess import Popen, PIPE
from exceptions import *
import re
import os
from datetime import datetime


class ShellCommand(object):
    """
    Класс, содержащий метод исполнения shell команд
    """

    binary = None

    def run_command(self, command, *args, **kwargs):
        """
        Выполняет комманду shell
        """
        params = ' '.join(args)
        named_params = ' '.join(['-%s %s' % (k, v) for k, v in kwargs.items() if v is not None])
        cmd = ' '.join([self.binary, command, params, named_params])
        proc = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
        return self._parse_response(*proc.communicate())

    def _parse_response(self, stdout, stderr):
        if stderr:
            if stderr.startswith('Empty certificate list'):
                return None
            else:
                raise ShellCommandError(stderr)
        return stdout


class Certmgr(ShellCommand):
    """
    Обертка над утилитой certmgr, входящей в состав Крипто-Про CSP (для UNIX-платформ).
    """

    def __init__(self, binary='/opt/cprocsp/bin/amd64/certmgr'):
        self.binary = binary

    def list(self, *args, **kwargs):
        """
        Возвращает список сертификатов
        """
        limit = kwargs.pop('limit', None)
        stdout = self.run_command('-list', *args, **kwargs)
        if stdout:
            return self._parse(stdout, limit)
        return []

    def inst(self, *args, **kwargs):
        """
        Устанавливает сертификат
        """
        return self.run_command('-inst', **kwargs)

    def delete(self, *args, **kwargs):
        """
        Удаляет сертификат
        """
        return self.run_command('-delete', **kwargs)

    def get(self, thumbprint, store='My'):
        """
        Возвращает информацию о сертификате
        """
        res = self.list(thumbprint=thumbprint, store=store)
        if res:
            return res[0]

    def _parse(self, text, limit=None):
        """
        Парсит stdout. Возвращает список экземпляров класса Certificate
        """
        res = []
        sep = re.compile(r'\d+-{7}')

        for i, item in enumerate(sep.split(text)[1:], start=1):
            cert_data = {}
            for line in item.split('\n'):
                if line == '':
                    continue

                if line.startswith('=='):
                    break

                key, val = self._get_key_and_val(line)
                cert_data[key] = val

            res.append(self._make_cert_object(cert_data))

            if limit and i == limit:
                break

        return res

    @staticmethod
    def _get_key_and_val(line):
        """
        Преобразует строку в пару ключ:значение
        """
        key, val = line.split(':', 1)
        key = key.strip().lower().replace(' ', '_')
        val = val.strip()

        if key in ('sha1_hash', 'serial'):
            val = val.replace('0x', '')

        return key, val

    @staticmethod
    def _make_cert_object(data):
        """
        Преобразует словарь с данными сертификата в объект
        """
        cert = Certificate(
            thumbprint=data['sha1_hash'],
            serial=data['serial'],
            valid_from=datetime.strptime(data['not_valid_before'], '%d/%m/%Y %H:%M:%S UTC'),
            valid_to=datetime.strptime(data['not_valid_after'], '%d/%m/%Y %H:%M:%S UTC'),
            issuer=data['issuer'],
            subject=data['subject']
        )
        return cert


class Certificate(object):
    """Сертификат"""

    def __init__(self, thumbprint, serial, valid_from, valid_to, issuer, subject):
        self.thumbprint = thumbprint
        self.serial = serial
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.issuer = issuer
        self.subject = subject


class Cryptcp(ShellCommand):
    """
    Обертка над утилитой cryptcp, входящей в состав Крипто-Про CSP (для UNIX-платформ).
    """

    def __init__(self, binary='/opt/cprocsp/bin/amd64/cryptcp'):
        self.binary = binary

    def _parse_response(self, stdout, stderr):
        if '[ReturnCode: 0]' in stdout:
            return stdout

        match = re.search(r'ErrorCode: (.+)]', stdout)
        if match:
            error_code = match.group(1)
            if error_code == '0x20000133':
                raise CertificateChainNotChecked(stdout)

            if error_code == '0x200001F9':
                raise InvalidSignature(stdout)

        raise ShellCommandError(stdout)

    def vsignf(self, *args, **kwargs):
        self.run_command('-vsignf', *args, **kwargs)

    def verify(self, sgn_dir, cert_filename, filename, errchain=True):
        """
        Проверяет электронную подпись.

        :param sgn_dir: путь к каталогу с подписью
        :param cert_filename: имя файла с сертификатом
        :param filename: имя подписываемого файла
        :param errchain: кидать ошибку если не удалось проверить хотя бы один элемент цепочки
        """

        file_path = os.path.join(sgn_dir, filename)
        args = [file_path]

        if errchain:
            args.append('-errchain')
        else:
            args.append('-nochain')

        kwargs = {
            'dir': sgn_dir,
            'f': os.path.join(sgn_dir, cert_filename)
        }

        try:
            self.run_command('-vsignf', *args, **kwargs)
        except CertificateChainNotChecked:
            return False

        except InvalidSignature:
            return False

        return True
