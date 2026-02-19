# coding: utf-8

from __future__ import absolute_import, unicode_literals

import ruamel.yaml

if False:  # MYPY
    from typing import Any  # NOQA

typ = 'jinja2'


class MyReader(ruamel.yaml.reader.Reader):
    def __init__(self, stream, loader):
        assert stream is None
        assert loader is not None
        ruamel.yaml.reader.Reader.__init__(self, stream, loader)

    @property
    def stream(self):
        return ruamel.yaml.reader.Reader.stream.fget(self)

    @stream.setter
    def stream(self, val):
        if val is None:
            return ruamel.yaml.reader.Reader.stream.fset(self, val)
        s = val.read() if hasattr(val, 'read') else val
        reverse = {}
        md = dict(reverse=reverse)
        setattr(self.loader, '_plug_in_' + typ, md)
        if_pat = ('{{- ', ' #<{- ')
        if if_pat[0] in s:
            s = s.replace(if_pat[0], if_pat[1])
            if if_pat not in reverse:
                reverse[if_pat[1]] = if_pat[0]
        len = 1
        for len in range(1, 10):
            pat = '<' * len + '{'
            if pat not in s:
                s = s.replace('{{', pat)
                reverse[pat] = '{{'
                break
        else:
            raise NotImplementedError('could not find substitute pattern ' + pat)
        len = 1
        for len in range(1, 10):
            pat = '#' * len + '%'
            if pat not in s:
                s = s.replace('{%', pat)
                reverse[pat] = '{%'
                break
        else:
            raise NotImplementedError('could not find substitute pattern ' + pat)
        return ruamel.yaml.reader.Reader.stream.fset(self, s)


class Rewriter:
    def __init__(self, out, md):
        """store what you need from the metadata"""
        self.reverse = md['reverse']
        self.out = out

    def write(self, data):
        """here the reverse work is done and then written to the original stream"""
        for k in self.reverse:
            try:
                data = data.replace(k, self.reverse[k])
            except TypeError:
                data = data.decode('utf-8')
            data = data.replace(k, self.reverse[k])
        self.out.write(data)


class MyEmitter(ruamel.yaml.emitter.Emitter):
    def __init__(self, *args, **kw):
        assert args[0] is None
        ruamel.yaml.emitter.Emitter.__init__(self, *args, **kw)

    @property
    def stream(self):
        return ruamel.yaml.emitter.Emitter.stream.fget(self)

    @stream.setter
    def stream(self, val):
        if val is None:
            return ruamel.yaml.emitter.Emitter.stream.fset(self, None)
        return ruamel.yaml.emitter.Emitter.stream.fset(
            self, Rewriter(val, getattr(self.dumper, '_plug_in_' + typ))
        )


def init_typ(self):
    self.Reader = MyReader
    self.Emitter = MyEmitter
    self.Serializer = ruamel.yaml.serializer.Serializer  # type: Any
    self.Representer = ruamel.yaml.representer.RoundTripRepresenter  # type: Any
    self.Scanner = ruamel.yaml.scanner.RoundTripScanner  # type: Any
    self.Parser = ruamel.yaml.parser.RoundTripParser  # type: Any
    self.Composer = ruamel.yaml.composer.Composer  # type: Any
    self.Constructor = ruamel.yaml.constructor.RoundTripConstructor  # type: Any


"""
class Sanitize:
    def __init__(self):
        self.accacc = None
        self.accper = None

    def __call__(self, s):
        len = 1
        for len in range(1, 10):
            pat = '<' * len + '{'
            if pat not in s:
                self.accacc = pat
                break
        else:
            raise NotImplementedError('could not find substitute pattern '+pat)
        len = 1
        for len in range(1, 10):
            pat = '#' * len + '%'
            if pat not in s:
                self.accper = pat
                break
        else:
            raise NotImplementedError('could not find substitute pattern '+pat)
        return s.replace('{{', self.accacc).replace('{%', self.accper)

    def revert(self, s):
        return s.replace(self.accacc, '{{').replace(self.accper, '{%')


def update_one(file_name, out_file_name=None):
    sanitize = Sanitize()
    with open(file_name) as fp:
        data = yaml.load(sanitize(fp.read()))
    myArray = data['A']['B'][1]['myArray']
    pos = myArray.index('val2')
    myArray.insert(pos+1, 'val 3')
    if out_file_name is None:
        yaml.dump(data, sys.stdout, transform=sanitize.revert)
    else:
        with open(out_file_name, 'w') as fp:
            yaml.dump(data, out, transform=sanitize.revert)

update_one('input.yaml')

"""
