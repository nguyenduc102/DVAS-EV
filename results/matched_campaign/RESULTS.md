# Matched DVAS measured-process campaign

Run settings are in config.json and environment.json, raw rows under runs/.

Independent fresh coordinator runs: 5.
Measured attempts: 29160. Harness errors: 0.
Unexpected outcomes: 0.

95% intervals resample independent run medians or P95s, 5,000 fixed-seed bootstrap draws. Five runs offer limited precision; raw session counts do not increase the independent-run count.

## Healthy results

|Method|Profile|Data|t/n|Protocol elapsed ms (95% run CI)|P95 ms|Public serialized B|Private application B|
|---|---|---|---|---|---|---|---|
|DVASSelectiveQuorum|C0|ACN|2/3|4.926 [4.882, 4.958]|5.252|5892|20687|
|DVASSelectiveQuorum|C0|ACN|3/5|5.775 [5.755, 5.900]|6.303|6759|37335|
|DVASSelectiveQuorum|C0|MFEV|2/3|5.010 [4.961, 5.037]|5.361|5856|20679|
|DVASSelectiveQuorum|C0|MFEV|3/5|5.910 [5.852, 7.427]|6.278|6714|37326|
|DVASSelectiveQuorum|C3|ACN|2/3|5.355 [5.306, 5.419]|5.765|19144|39730|
|DVASSelectiveQuorum|C3|ACN|3/5|6.597 [6.567, 6.605]|7.024|20011|90232|
|DVASSelectiveQuorum|C3|MFEV|2/3|5.459 [5.436, 5.477]|5.925|19108|39723|
|DVASSelectiveQuorum|C3|MFEV|3/5|6.690 [6.668, 6.765]|7.112|19965|90225|
|FullEvidenceQuorum|C0|ACN|2/3|5.023 [4.986, 5.200]|5.388|5962|20620|
|FullEvidenceQuorum|C0|ACN|3/5|5.921 [5.919, 6.048]|6.348|6828|37220|
|FullEvidenceQuorum|C0|MFEV|2/3|5.100 [5.054, 5.970]|5.436|5907|20589|
|FullEvidenceQuorum|C0|MFEV|3/5|6.017 [5.952, 6.110]|6.431|6765|37175|
|FullEvidenceQuorum|C3|ACN|2/3|5.497 [5.446, 5.568]|5.911|19214|39664|
|FullEvidenceQuorum|C3|ACN|3/5|6.735 [6.643, 6.818]|7.176|20080|90125|
|FullEvidenceQuorum|C3|MFEV|2/3|5.586 [5.532, 5.778]|6.027|19160|39633|
|FullEvidenceQuorum|C3|MFEV|3/5|6.807 [6.792, 7.041]|7.285|20017|90074|
|FullTranscriptEscrow|C0|ACN|2/3|2.251 [2.234, 2.280]|2.522|5765|0|
|FullTranscriptEscrow|C0|ACN|3/5|2.263 [2.246, 2.313]|2.536|5765|0|
|FullTranscriptEscrow|C0|MFEV|2/3|2.298 [2.282, 2.324]|2.567|5720|0|
|FullTranscriptEscrow|C0|MFEV|3/5|2.319 [2.277, 2.365]|2.560|5719|0|
|FullTranscriptEscrow|C3|ACN|2/3|2.670 [2.655, 2.683]|3.006|19017|0|
|FullTranscriptEscrow|C3|ACN|3/5|2.676 [2.675, 2.707]|2.958|19017|0|
|FullTranscriptEscrow|C3|MFEV|2/3|2.712 [2.694, 2.730]|2.974|18972|0|
|FullTranscriptEscrow|C3|MFEV|3/5|2.729 [2.705, 3.102]|3.066|18971|0|

Full scenario/rejection/CPU/memory results are in validation.csv, summary_uncertainty.csv and resource_summary.csv. See METHODOLOGY.md for interpretation.
