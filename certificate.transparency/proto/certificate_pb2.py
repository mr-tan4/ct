# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: certificate.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import client_pb2 as client__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='certificate.proto',
  package='ctpy',
  syntax='proto2',
  serialized_options=None,
  serialized_pb=_b('\n\x11\x63\x65rtificate.proto\x12\x04\x63tpy\x1a\x0c\x63lient.proto\"1\n\x08Validity\x12\x12\n\nnot_before\x18\x01 \x01(\x04\x12\x11\n\tnot_after\x18\x02 \x01(\x04\">\n\x12SignatureAlgorithm\x12\x14\n\x0c\x61lgorithm_id\x18\x01 \x01(\t\x12\x12\n\nparameters\x18\x02 \x01(\x0c\"*\n\x0b\x44NAttribute\x12\x0c\n\x04type\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t\"\xe9\x03\n\x0fX509Description\x12\x0f\n\x07version\x18\x01 \x01(\t\x12\x15\n\rserial_number\x18\x02 \x01(\t\x12/\n\rtbs_signature\x18\x03 \x01(\x0b\x32\x18.ctpy.SignatureAlgorithm\x12\x30\n\x0e\x63\x65rt_signature\x18\x04 \x01(\x0b\x32\x18.ctpy.SignatureAlgorithm\x12 \n\x08validity\x18\x05 \x01(\x0b\x32\x0e.ctpy.Validity\x12\"\n\x07subject\x18\x06 \x03(\x0b\x32\x11.ctpy.DNAttribute\x12!\n\x06issuer\x18\x07 \x03(\x0b\x32\x11.ctpy.DNAttribute\x12\x34\n\x19subject_alternative_names\x18\x08 \x03(\x0b\x32\x11.ctpy.DNAttribute\x12\x0b\n\x03\x64\x65r\x18\t \x01(\x0c\x12\x13\n\x0bsha256_hash\x18\n \x01(\x0c\x12&\n\x0broot_issuer\x18\x0c \x03(\x0b\x32\x11.ctpy.DNAttribute\x12&\n\nentry_type\x18\r \x01(\x0e\x32\x12.ctpy.LogEntryType\x12\x1b\n\x13\x62\x61sic_constraint_ca\x18\x0e \x01(\x08\x12\x1d\n\x15issuer_pk_sha256_hash\x18\x0f \x01(\x0c')
  ,
  dependencies=[client__pb2.DESCRIPTOR,])




_VALIDITY = _descriptor.Descriptor(
  name='Validity',
  full_name='ctpy.Validity',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='not_before', full_name='ctpy.Validity.not_before', index=0,
      number=1, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='not_after', full_name='ctpy.Validity.not_after', index=1,
      number=2, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=41,
  serialized_end=90,
)


_SIGNATUREALGORITHM = _descriptor.Descriptor(
  name='SignatureAlgorithm',
  full_name='ctpy.SignatureAlgorithm',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='algorithm_id', full_name='ctpy.SignatureAlgorithm.algorithm_id', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='parameters', full_name='ctpy.SignatureAlgorithm.parameters', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=92,
  serialized_end=154,
)


_DNATTRIBUTE = _descriptor.Descriptor(
  name='DNAttribute',
  full_name='ctpy.DNAttribute',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='ctpy.DNAttribute.type', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='ctpy.DNAttribute.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=156,
  serialized_end=198,
)


_X509DESCRIPTION = _descriptor.Descriptor(
  name='X509Description',
  full_name='ctpy.X509Description',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='version', full_name='ctpy.X509Description.version', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='serial_number', full_name='ctpy.X509Description.serial_number', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='tbs_signature', full_name='ctpy.X509Description.tbs_signature', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='cert_signature', full_name='ctpy.X509Description.cert_signature', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='validity', full_name='ctpy.X509Description.validity', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='subject', full_name='ctpy.X509Description.subject', index=5,
      number=6, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='issuer', full_name='ctpy.X509Description.issuer', index=6,
      number=7, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='subject_alternative_names', full_name='ctpy.X509Description.subject_alternative_names', index=7,
      number=8, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='der', full_name='ctpy.X509Description.der', index=8,
      number=9, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sha256_hash', full_name='ctpy.X509Description.sha256_hash', index=9,
      number=10, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='root_issuer', full_name='ctpy.X509Description.root_issuer', index=10,
      number=12, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='entry_type', full_name='ctpy.X509Description.entry_type', index=11,
      number=13, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='basic_constraint_ca', full_name='ctpy.X509Description.basic_constraint_ca', index=12,
      number=14, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='issuer_pk_sha256_hash', full_name='ctpy.X509Description.issuer_pk_sha256_hash', index=13,
      number=15, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=201,
  serialized_end=690,
)

_X509DESCRIPTION.fields_by_name['tbs_signature'].message_type = _SIGNATUREALGORITHM
_X509DESCRIPTION.fields_by_name['cert_signature'].message_type = _SIGNATUREALGORITHM
_X509DESCRIPTION.fields_by_name['validity'].message_type = _VALIDITY
_X509DESCRIPTION.fields_by_name['subject'].message_type = _DNATTRIBUTE
_X509DESCRIPTION.fields_by_name['issuer'].message_type = _DNATTRIBUTE
_X509DESCRIPTION.fields_by_name['subject_alternative_names'].message_type = _DNATTRIBUTE
_X509DESCRIPTION.fields_by_name['root_issuer'].message_type = _DNATTRIBUTE
_X509DESCRIPTION.fields_by_name['entry_type'].enum_type = client__pb2._LOGENTRYTYPE
DESCRIPTOR.message_types_by_name['Validity'] = _VALIDITY
DESCRIPTOR.message_types_by_name['SignatureAlgorithm'] = _SIGNATUREALGORITHM
DESCRIPTOR.message_types_by_name['DNAttribute'] = _DNATTRIBUTE
DESCRIPTOR.message_types_by_name['X509Description'] = _X509DESCRIPTION
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Validity = _reflection.GeneratedProtocolMessageType('Validity', (_message.Message,), dict(
  DESCRIPTOR = _VALIDITY,
  __module__ = 'certificate_pb2'
  # @@protoc_insertion_point(class_scope:ctpy.Validity)
  ))
_sym_db.RegisterMessage(Validity)

SignatureAlgorithm = _reflection.GeneratedProtocolMessageType('SignatureAlgorithm', (_message.Message,), dict(
  DESCRIPTOR = _SIGNATUREALGORITHM,
  __module__ = 'certificate_pb2'
  # @@protoc_insertion_point(class_scope:ctpy.SignatureAlgorithm)
  ))
_sym_db.RegisterMessage(SignatureAlgorithm)

DNAttribute = _reflection.GeneratedProtocolMessageType('DNAttribute', (_message.Message,), dict(
  DESCRIPTOR = _DNATTRIBUTE,
  __module__ = 'certificate_pb2'
  # @@protoc_insertion_point(class_scope:ctpy.DNAttribute)
  ))
_sym_db.RegisterMessage(DNAttribute)

X509Description = _reflection.GeneratedProtocolMessageType('X509Description', (_message.Message,), dict(
  DESCRIPTOR = _X509DESCRIPTION,
  __module__ = 'certificate_pb2'
  # @@protoc_insertion_point(class_scope:ctpy.X509Description)
  ))
_sym_db.RegisterMessage(X509Description)


# @@protoc_insertion_point(module_scope)
