# coding: utf-8

from subprocess import Popen, PIPE
from pycryptopro.exceptions import *
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

    def get(self, thumbprint, store='uMy'):
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
                if line == '' or ':' not in line:
                    continue

                if line.startswith('=='):
                    break

                key, val = self._parse_line(line)
                cert_data[key] = val

            res.append(self._make_cert_object(cert_data))

            if limit and i == limit:
                break

        return res

    @staticmethod
    def _parse_line(line):
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

        def _str_to_datetime(string):
            return datetime.strptime(string, '%d/%m/%Y %H:%M:%S UTC')

        cert = Certificate(
            thumbprint=data['sha1_hash'],
            serial=data['serial'],
            valid_from=_str_to_datetime(data['not_valid_before']),
            valid_to=_str_to_datetime(data['not_valid_after']),
            issuer=PersonalInfo(data['issuer']),
            subject=PersonalInfo(data['subject'])
        )
        return cert


class PersonalInfo(object):
    def __init__(self, line):
        self.line = line

    def as_string(self):
        return self.line

    def as_dict(self):
        return self._parse(self.line)

    @staticmethod
    def _parse(line):
        data = {}
        for item in line.split(', '):
            try:
                k, v = item.split('=')
                data[k] = v
            except:
                pass
        return data

    def __repr__(self):
        return self.as_string()


class Certificate(object):
    """
    Сертификат
    """

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
            error_code = match.group(1).lower()
            if error_code == '0x20000133':
                raise CertificateChainNotChecked(stdout)

            if error_code in ('0x200001f9', '0x2000012d'):
                raise InvalidSignature(stdout)

        raise ShellCommandError(stdout)

    def sign(self, filename, thumbprint, cert=True):
        """
        Создает отделенную подпись файла.
        Подпись создается в каталоге, в котором находится подписываемый файл.

        :param filename: файл, для которого создается подпись
        :param thumbprint: отпечаток сертификата, которым создается подпись
        :param cert: включать или нет сертификат владельца в подпись
        """

        dirname = os.path.dirname(filename)

        args = [filename]

        if cert:
            args.append('-cert')

        kwargs = {
            'dir': dirname,
            'thumbprint': thumbprint
        }

        self.run_command('-signf', *args, **kwargs)

    def verify(self, sgn_dir, cert_filename, filename, errchain=True, norev=False):
        """
        Проверяет отделенную электронную подпись.

        :param sgn_dir: путь к каталогу с подписью
        :param cert_filename: имя файла с сертификатом
        :param filename: имя подписываемого файла
        :param errchain: кидать ошибку если не удалось проверить цепочку сертификатов
        """

        file_path = os.path.join(sgn_dir, filename)
        args = [file_path]

        if errchain:
            args.append('-errchain')
        else:
            args.append('-nochain')

        if norev:
            args.append('-norev')

        kwargs = {
            'dir': sgn_dir,
            'f': os.path.join(sgn_dir, cert_filename)
        }

        self.run_command('-vsignf', *args, **kwargs)
