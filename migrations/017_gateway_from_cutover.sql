-- 017_gateway_from_cutover.sql  (2026-11-20)
--
-- The collector was cut over at a time on 2026-11-20, after the sensor began
-- presenting the file-transfer gateway at about 13:50 UTC. Nothing before the
-- cut is kept, so the epoch starting that day is the gateway, and no separate
-- epoch is needed for the next day. Earlier data lives in the archive copy.

DELETE FROM persona_epochs WHERE start_day = '2026-11-21';

UPDATE persona_epochs
   SET name = 'File-transfer gateway',
       note = 'Sensor presents a file-transfer gateway persona from a US '
           || 'address. The collector keeps data from the cutover time on '
           || 'this day; everything earlier was archived off it.'
 WHERE start_day = '2026-11-20' AND name <> 'File-transfer gateway';
