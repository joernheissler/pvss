.. _math.operations:

Operations
==========

The protocol consists of six steps which are executed in sequence.
The last three steps can be repeated if another reconstruction is desired.

Each step requires the public input from all previous steps.

Recipients of public values must check if those values conform to this protocol, e.g.
if groups are really of prime order and if group members really are inside the group.

Recipients of public values must also ensure that those value were not modified by a third party.
How to accomplish this is out of scope of this chapter.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   initialization
   user-keypair
   secret-splitting
   receiver-keypair
   reencryption
   reconstruction
