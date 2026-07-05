# Unsafe deserialization: pickle.loads on untrusted request bytes is RCE.
import pickle
def restore(request):
    blob = request.data
    return pickle.loads(blob)  # nox-expect: TAINT-005
