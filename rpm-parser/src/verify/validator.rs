use rpm_crypto::transaction::RpmKeyring;
use rpm_crypto::{DigestCtx, Signature};
use std;
use std::io::{Result, Write};

/// Something that can be cryptographically verified
enum Verifyable {
    /// An untrusted digest
    UntrustedDigest(DigestCtx, Vec<u8>),
    /// A signature
    Signature(Signature),
    /// A trusted digest
    TrustedDigest(DigestCtx, Vec<u8>),
}

impl Verifyable {
    fn update(&mut self, data: &[u8]) {
        match self {
            &mut Verifyable::UntrustedDigest(ref mut dgst, _)
            | &mut Verifyable::TrustedDigest(ref mut dgst, _) => dgst.update(data),
            &mut Verifyable::Signature(ref mut sig) => sig.update(data),
        }
    }

    fn trusted(&self) -> bool {
        match self {
            &Verifyable::Signature(_) | &Verifyable::TrustedDigest(_, _) => true,
            &Verifyable::UntrustedDigest(_, _) => false,
        }
    }
}

pub(super) struct Validator<'a> {
    objects: Vec<Verifyable>,
    output: Option<&'a mut dyn Write>,
}

impl<'a> Write for Validator<'a> {
    /// Update the digests and signatures within with the provided data.
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        let len = match self.output {
            None => data.len(),
            Some(ref mut output) => output.write(data)?,
        };
        for i in &mut self.objects {
            i.update(&data[..len])
        }
        Ok(len)
    }
    fn flush(&mut self) -> Result<()> {
        match self.output {
            None => Ok(()),
            Some(ref mut s) => s.flush(),
        }
    }
}

impl<'a> Validator<'a> {
    /// Creates a [`Validator`]
    pub(super) fn new(output: Option<&'a mut dyn Write>) -> Self {
        Self {
            objects: vec![],
            output,
        }
    }

    /// Sets the [`std::io::Write`] that this [`Validator`] will write bytes to.  The bytes are
    /// untrusted at this point.
    ///
    /// Returns the old writer.
    pub(super) fn set_output(
        &mut self,
        output: Option<&'a mut dyn Write>,
    ) -> Option<&'a mut dyn Write> {
        std::mem::replace(&mut self.output, output)
    }

    /// Add an untrusted digest.  An incorrect untrusted digest will result in verification
    /// failure, but a correct untrusted digest is not sufficient.
    pub(super) fn add_untrusted_digest(&mut self, dgst: DigestCtx, data: Vec<u8>) -> &mut Self {
        self.objects.push(Verifyable::UntrustedDigest(dgst, data));
        self
    }

    /// Add a signature.  Signatures are always considered trusted.
    pub(super) fn add_signature(&mut self, sig: Signature) -> &mut Self {
        self.objects.push(Verifyable::Signature(sig));
        self
    }

    /// Add a trusted digest.  Trusted digests are considered to be as strong as a signature.
    /// Therefore, the data being verified must come from a trusted source.
    ///
    /// For example, it is safe to use a digest that comes from a header signed with a trusted
    /// signature.
    pub(super) fn add_trusted_digest(&mut self, dgst: DigestCtx, data: Vec<u8>) -> &mut Self {
        self.objects.push(Verifyable::TrustedDigest(dgst, data));
        self
    }

    /// Consume [`self`] and validate the signatures and/or digests contained theirin.
    ///
    /// This will return [`Ok`] only if both of the following conditions are met:
    ///
    /// - All digests and signatures must validate correctly.
    /// - [`self`] must contain either a signature or a trusted digest.
    pub(super) fn validate(self, keyring: &RpmKeyring) -> std::result::Result<(), ()> {
        let mut trusted = false;
        let mut no_bad_found = true;
        for i in self.objects.into_iter() {
            trusted |= i.trusted();
            no_bad_found &= match i {
                Verifyable::TrustedDigest(ctx, digest)
                | Verifyable::UntrustedDigest(ctx, digest) => {
                    ctx.finalize((digest.len() & 1) != 0) == digest
                }
                Verifyable::Signature(sig) => keyring.validate_sig(sig).is_ok(),
            };
        }
        if trusted && no_bad_found {
            Ok(())
        } else {
            Err(())
        }
    }
}
