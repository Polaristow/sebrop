import levrt
from levrt import Cr, annot, ctx, remote
from levrt.annot.cats import Attck, BlackArch
from . import sebrop


__lev__ = annot.meta([sebrop],
                     desc="sebrop",
                     cats={
                         Attck: [Attck.Reconnaissance],
                         BlackArch: [BlackArch.Scanner, BlackArch.Cracker]
                     })

