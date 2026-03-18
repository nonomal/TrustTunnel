use rand::Rng;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    EmptyMask,
    InvalidLength(usize),
    InvalidPercent(u8),
    MaskTooLong(usize),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyMask => write!(f, "mask must not be empty"),
            Self::InvalidLength(length) => {
                write!(f, "length must be in range 1..=32 bytes, got {}", length)
            }
            Self::InvalidPercent(percent) => {
                write!(f, "percent must be in range 1..=100, got {}", percent)
            }
            Self::MaskTooLong(length) => {
                write!(f, "mask length must be in range 1..=32 bytes, got {}", length)
            }
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratorParams {
    pub length: usize,
    pub percent: u8,
}

impl Default for GeneratorParams {
    fn default() -> Self {
        Self {
            length: 4,
            percent: 70,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedPrefix {
    value: Vec<u8>,
    mask: Vec<u8>,
}

impl GeneratedPrefix {
    pub fn new(value: Vec<u8>, mask: Vec<u8>) -> Result<Self, Error> {
        validate_mask(&mask)?;

        Ok(Self { value, mask })
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn mask(&self) -> &[u8] {
        &self.mask
    }

    pub fn to_masked_hex_string(&self) -> String {
        format!("{}/{}", hex::encode(&self.value), hex::encode(&self.mask))
    }
}

pub fn generate(params: GeneratorParams) -> Result<GeneratedPrefix, Error> {
    validate_params(params)?;

    let mask = generate_mask(params.length, params.percent);
    let value = generate_value(&mask);

    GeneratedPrefix::new(value, mask)
}

pub fn generate_with_mask(mask: Vec<u8>) -> Result<GeneratedPrefix, Error> {
    validate_mask(&mask)?;

    let value = generate_value(&mask);

    GeneratedPrefix::new(value, mask)
}

fn validate_params(params: GeneratorParams) -> Result<(), Error> {
    if !(1..=32).contains(&params.length) {
        return Err(Error::InvalidLength(params.length));
    }

    if !(1..=100).contains(&params.percent) {
        return Err(Error::InvalidPercent(params.percent));
    }

    Ok(())
}

fn validate_mask(mask: &[u8]) -> Result<(), Error> {
    if mask.is_empty() {
        return Err(Error::EmptyMask);
    }

    if mask.len() > 32 {
        return Err(Error::MaskTooLong(mask.len()));
    }

    Ok(())
}

fn generate_mask(length: usize, percent: u8) -> Vec<u8> {
    let mut mask = vec![0u8; length];
    let mut rng = rand::thread_rng();

    for byte in &mut mask {
        for bit in 0..8 {
            if rng.gen_range(0..100) < percent {
                *byte |= 1 << bit;
            }
        }
    }

    mask
}

fn generate_value(mask: &[u8]) -> Vec<u8> {
    let mut value = vec![0u8; mask.len()];
    let mut rng = rand::thread_rng();

    for (byte, mask_byte) in value.iter_mut().zip(mask.iter().copied()) {
        *byte = rng.gen::<u8>() & mask_byte;
    }

    value
}
