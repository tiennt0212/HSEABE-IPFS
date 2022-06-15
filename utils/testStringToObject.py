from HSEABE import HSEABE

srlPublicKey = "{\"e_gh_kA\": [\"3:MLQoklInnmTwZIT0+27hIO90j+p936dpSX8/ppmk602fFwPP7/rYDuQW/movKEm+TvYw3OadDQdend417yL24pXQ4JQRXYKx5DqK1JPZ74T8imKv60g7GxmLGu4oju1K876svTKWh5gkf+hv+aIxdsl23Zp0rFbs5kZ6KpbS3A0=\", \"3:UB9qK9UvFd2h3QX/L/PTc4Ryg0E1h1VIT6vifDCvXhy4kp8kLAak7dwzNGFiNWtJ5noAyHR+0qM2uFSwUuziPgXDxejP4YwlliBUl24C+LA6Rl5Eb4KbAuZdPs8SsxWAuuF+kHX3+b7mX3TxKSHh+0v2mJnwpvyxzbqrgXMOB6U=\"], \"h_A\": [\"2:HsgKy9lTrzdJIDA0Sn9os4uSUP/g2e8pHRvxIqzHLDLMtM65Yx6k8ZIBXZ3Qvbc0cMprExFJ6D1KN46ub+MQNQE=\", \"2:ZG8q6c5zRVcP8XFpP1HJMJOnGJ3Nh6vEKwEmPJnCHTFCdEKQ3uS7Rq+Sgb8h6g2jOLThIgdEqF+w64AERCWDUwE=\", \"2:fLrhjdIQucrW72gh2pm6Z1dK5VFUVlfJrDcmcqCKYXYX4wLt+GfNYS8JPzzLP8A3HHcXGvF+7vd6KtPXeEBK1gA=\"]}"

print(HSEABE()._stringToObject(srlPublicKey))

print(type(HSEABE()._stringToObject(srlPublicKey)))