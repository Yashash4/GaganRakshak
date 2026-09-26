"""Register the GaganRakshak messages (gaganrakshak.xml) into pymavlink's ardupilotmega and
"all" dialects (mavutil's default), so every parser in the chain (routers, radio, IDS, tlog replay) decodes them.
Regenerate gr_dialect.py after editing the XML:
    python -m pymavlink.tools.mavgen --lang Python3 --wire-protocol 2.0 \
        -o gaganrakshak/mavlink/gr_dialect.py gaganrakshak/mavlink/gaganrakshak.xml
"""

from pymavlink.dialects.v10 import all as _v10all
from pymavlink.dialects.v10 import ardupilotmega as _v10
from pymavlink.dialects.v20 import all as _v20all
from pymavlink.dialects.v20 import ardupilotmega as _v20

from . import gr_dialect as gr

for _mod in (_v10, _v20, _v10all, _v20all):
    _mod.mavlink_map.update(gr.mavlink_map)
    for _name in dir(gr):
        if _name.startswith(("MAVLink_gr_", "MAVLINK_MSG_ID_GR_")):
            setattr(_mod, _name, getattr(gr, _name))
