// use franklin_crypto::bellman::bls12_381::Bls12;
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
    Circuit, ConstraintSystem, Width4MainGateWithDNext,
};
// use franklin_crypto::bellman::plonk::better_better_cs::cs::{Gate, GateInternal};
use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::circuit::Assignment;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
// use franklin_crypto::plonk::circuit::bigint::range_constraint_gate::TwoBitDecompositionRangecheckCustomGate;
use generic_array::{typenum::*, ArrayLength, GenericArray};
use verkle_tree::ipa_fr::utils::{read_field_element_be, read_field_element_le};

/// This is the circuit implementation of the Poseidon hash function.
/// * `width` is also known as the parameter `t`.
/// The default width is 2 (N = U2).
/// * The length of `inputs` must be `width - 1`.
/// * `output` must be the Poseidon hash of `inputs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoseidonCircuit<E, N = U2>
where
    E: Engine,
    N: ArrayLength<Option<E::Fr>>,
{
    pub inputs: GenericArray<Option<E::Fr>, N>, // [Option<E::Fr>; N::to_usize()]
    pub output: Option<E::Fr>,
}

impl<E: Engine, N: ArrayLength<Option<E::Fr>>> Circuit<E> for PoseidonCircuit<E, N> {
    type MainGate = Width4MainGateWithDNext;

    // fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
    //     Ok(vec![
    //         Self::MainGate::default().into_internal(),
    //         TwoBitDecompositionRangecheckCustomGate::default().into_internal(),
    //     ])
    // }

    fn synthesize<CS>(&self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        assert_eq!(self.inputs.len(), N::to_usize(), "invalid inputs length");

        let inputs = self
            .inputs
            .iter()
            .map(|x| AllocatedNum::alloc(cs, || Ok(*x.get()?)))
            .collect::<Result<Vec<_>, SynthesisError>>()?;
        let result = calc_poseidon(cs, &inputs)?;
        let output = AllocatedNum::alloc_input(cs, || Ok(*self.output.get()?))?;
        result.sub(cs, &output)?.assert_is_zero(cs)?;

        Ok(())
    }
}

// pub fn calc_sigma<E, CS>(
//   cs: &mut CS,
//   input: AllocatedNum<E>,
//   alpha: usize,
// ) -> Result<AllocatedNum<E>, SynthesisError>
// where
//   E: Engine,
//   CS: ConstraintSystem<E>,
// {
//   let mut alpha_bits = vec![];
//   while alpha != 0 {
//     alpha_bits.push(alpha & 1 == 1);
//     alpha >>= 1;
//   }
//   // let alpha_bits = [true, false, true];
//   let mut output = if alpha_bits[0] {
//     input.clone()
//   } else {
//     AllocatedNum::<E>::one(cs)
//   };
//   let mut power = input;
//   for b in alpha_bits.iter().skip(1) {
//     power = power.square(cs)?;
//     if *b {
//       output = output.mul(cs, &power)?;
//     }
//   }

//   Ok(output)
// }

/// Generate constraints that
/// `output` = `input` ** `alpha`.
///
/// This function is required that `alpha` (= 5) is relatively prime to the order `p` of `E::Fr`.
pub fn calc_sigma<E, CS>(
    cs: &mut CS,
    input: AllocatedNum<E>,
) -> Result<AllocatedNum<E>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let input2 = input.square(cs)?;
    let input4 = input2.square(cs)?;
    let input5 = input4.mul(cs, &input)?;

    Ok(input5)
}

/// Generate constraints that
/// `output` = `input` + `C[r]`.
pub fn add_round_constant<E, CS>(
    cs: &mut CS,
    input: AllocatedNum<E>,
    r: usize,
) -> Result<AllocatedNum<E>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let reader = hex::decode(&C[r][2..]).unwrap();
    let c = read_field_element_be::<E::Fr>(&reader).unwrap();
    let output = input.add_constant(cs, c)?;

    Ok(output)
}

/// Generate constraints that
/// `outputs` = `inputs` * `m` (matrix multiplication).
pub fn product_mds_with_matrix<E, CS>(
    cs: &mut CS,
    inputs: &[AllocatedNum<E>],
    m: &[[&str; T]; T],
) -> Result<Vec<AllocatedNum<E>>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let mut outputs = vec![];
    let zero = AllocatedNum::zero(cs);

    for i in 0..T {
        let mut lc = zero;
        for j in 0..T {
            let m_reader = hex::decode(&m[j][i][2..]).unwrap();
            let wrapped_m =
                AllocatedNum::alloc_cnst(cs, read_field_element_be::<E::Fr>(&m_reader).unwrap())?;
            let tmp = inputs[j].mul(cs, &wrapped_m)?; // tmp = inputs[j] * M[j][i]
            lc = lc.add(cs, &tmp)?;
        }

        outputs.push(lc);
    }

    Ok(outputs)
}

// pub fn product_mds_with_sparse_matrix<E, CS>(
//   cs: &mut CS,
//   inputs: &[AllocatedNum<E>],
//   m: &SparseMatrix,
// ) -> Result<Vec<AllocatedNum<E>>, SynthesisError>
// where
//   E: Engine,
//   CS: ConstraintSystem<E>,
// {
//   let zero = AllocatedNum::zero(cs);
//   let mut result = vec![zero; T];

//   // First column is dense.
//   for (i, val) in m.w_hat.iter().enumerate() {
//     let m_reader = hex::decode(&val[2..]).unwrap();
//     let wrapped_m = AllocatedNum::alloc_cnst(cs, read_field_element_be::<E::Fr>(&m_reader).unwrap())?;
//     let tmp = wrapped_m.mul(cs, &inputs[i])?;
//     result[0].add(cs, &tmp)?;
//   }

//   for (j, val) in result.iter_mut().enumerate().skip(1) {
//     // Except for first row/column, diagonals are one.
//     let tmp = inputs[j].add(cs, &val)?;

//     // First row is dense.
//     let m_reader = hex::decode(&m.v_rest[j - 1][2..]).unwrap();
//     let wrapped_m = AllocatedNum::alloc_cnst(cs, read_field_element_be::<E::Fr>(&m_reader).unwrap())?;
//     let new_val = wrapped_m.mul(cs, &inputs[0])?.add(cs, &tmp)?;
//     let _old_val = std::mem::replace(val, new_val);
//   }

//   Ok(result)
// }

/// Generate constraints for Poseidon hash.
pub fn calc_poseidon<E, CS>(
    cs: &mut CS,
    inputs: &[AllocatedNum<E>],
) -> Result<AllocatedNum<E>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let input_num = T - 1;
    assert_eq!(inputs.len(), input_num, "invalid inputs length");

    let domain_tag = read_field_element_le::<E::Fr>(&[3]).unwrap();
    let wrapped_domain_tag = AllocatedNum::alloc_cnst(cs, domain_tag)?;
    let mut elements = vec![wrapped_domain_tag];
    elements.append(&mut inputs.to_vec());

    let half_full_rounds = N_ROUNDS_F / 2;
    for i in 0..(N_ROUNDS_F + N_ROUNDS_P) {
        for (j, e) in elements.iter_mut().enumerate() {
            let tmp = add_round_constant(cs, *e, j + T * i)?;
            let _ = std::mem::replace(e, tmp);
        }

        if i < half_full_rounds || i >= half_full_rounds + N_ROUNDS_P {
            // full round
            for e in elements.iter_mut() {
                let tmp = calc_sigma(cs, *e)?;
                let _ = std::mem::replace(e, tmp);
            }
        } else {
            // partial round
            elements[0] = calc_sigma(cs, elements[0])?;
            // for j in 1..T {
            //   tmp[j] = tmp[j];
            // }
        }

        elements = product_mds_with_matrix(cs, &elements, &M)?;
    }

    // TODO: last round is done only for the first word, so we do it manually to save constraints
    // for j in 0..T {
    //   elements[j] = calc_sigma(cs, elements[j])?;
    // }
    // let elements = product_mds_with_matrix(cs, &elements, &M)?;

    Ok(elements[1])
}

const T: usize = 3; // width
const N_ROUNDS_F: usize = 8; // full_rounds
const N_ROUNDS_P: usize = 55; // partial_rounds

/// round_constants
/// https://github.com/filecoin-project/neptune
const C: [&str; T * (N_ROUNDS_F + N_ROUNDS_P)] = [
    "0x1051abd795bb781c5bcb3d4c7320b88f033cb1904c5b8559bf08995be4d6305d",
    "0x2680c4e5e102394a8c53c7ca99003cbeb3422caedbfa62c2373862e367a3dd00",
    "0x132e8252ba372e32578a441ca6b0865f73d890c968dd8b7642f5b483676160b6",
    "0x0dff6973df3b1f559d2e21ede06b857c63e4da1bd50a03e4d500e226dd108be7",
    "0x05e9463e0290d75eb2948587b1f9a7ca52ea91c9e57b322cdfab3c4822f1abbd",
    "0x2365c6a8b9928e31609cb8190336a6a2eebf69b015bc7958840576fd4e42da38",
    "0x16aa8ba01611f750811cbb3d4257f53a969fccaec3130b7a6441c39c9bae8458",
    "0x2717b1a58bf1978c6af4069069429e64ea024efd3b9be8fe8aa2bf1d8c28f42d",
    "0x2d26bd604c702d7c74850099492efb38bc836c3cb88602e1679ddb53557292bf",
    "0x174a4de6c44cab3c9781597fa27c024f7c7a114632a541ed7fed2deb245a85e1",
    "0x1d3e5ecbb083875c59541464dc6e7d1a59b4f68d985a213b28314a3004ec6809",
    "0x014edb6e589987b69e282db5f52c1b0bbe8704e601154c6a0afe84b52f9a4aae",
    "0x0e0d8d1e063d74b601a548eae7d368fd8ac907dd9145beaf63f2e2a6a28fccd5",
    "0x0602ae8ffb9d13f3cce1e3ae3c2f494b03d3fc2fc6426d5fe6cc1c312d068da2",
    "0x23868f037d108e9346a8d63130d6d9aab87e701c1828c574fa67cc8c1177a6b3",
    "0x1073b5a9ce850e2d6f16e5776b4ee254146ed65bbd8f50d36e17747778af00d2",
    "0x073da226b5a2639fe26496cdc3dbd5fd769984dc39e44003781d9140596543c4",
    "0x2cfbfacaaab3b3526fd0dc6d369646f3fe3948da0fa8a132f0dbde96b5ddc9e6",
    "0x0fc0855a69b277b726ac164b86ffba19954c0d59802838c4f032df5ca38ae88e",
    "0x2649f096f1e407adbe09b44a07c54ec03f23cdef4b1e4c96d81f632df917e0e0",
    "0x0f9c0aa8c10f48a205c7ed49d1cffa12829b53ac76840f3a0aff6cb10418ca40",
    "0x11547a7f704f1eb0394663d4afc2fe19823910bebe3147b6f0ffb7f8433838e1",
    "0x16aff7c7076d3487c8d10e640da7652a5f3a007967eaa7282ced25e89b61787d",
    "0x011a06492822359dbd9406c3afba3bfa469147f483f0ae78c80f9077de480b86",
    "0x0d7f084fe4f168dd3b06a36866399b1c4c3c6a7f247f317d8463d9e447608134",
    "0x078b6029f46dc32407770079ff46c9b20accea7cd0120ef5fdca18a7cb65b127",
    "0x2dea4e22de864b493684aebb0a692f939ce841aebf83330c13f2ee57071793ae",
    "0x08cbcba0c91b3981c0207f75e4b0f032feaf5480e4aa243c946d938a2a57645f",
    "0x02d8f99ea79dbde1025ea741c56c3e6978e7eb7b820eb30148d6c059bb8c365e",
    "0x109b2d0bcdbd121d2764beeec0284a1b13cdb171ab316e729f6980adb7e219a3",
    "0x06a25826dc6271bf8c924962da4cda44dc320d0c66f31fd2efef0bd9b9f8fe35",
    "0x1a63e4e11c99ecbb52b14e202fd651a9872e560e9403fa2d9f33d20bcc32bca4",
    "0x03fb5deb4cdadf1ce955fa3c091f2dfb8c58951760769d1484f06ccf3a687d5b",
    "0x0bdac171754f43976c5cafd607771b9c7704e9d1c5576b87fe2aa0d80ab0fe01",
    "0x253a502bcfb721c80a2774434713ef20fad993dc5751c0673f44ef976d5ce751",
    "0x0e21300aec534829255add130d31da0dc54282656e893cba45b81b123671c2c5",
    "0x0d9d748361f6bbb3782751508fd274913d9153eff951dba21f3b20e69f229a36",
    "0x1eafe91d860ad0794059d7abe25ffa38d1e0229f64f81d34eeffadb1575edfc8",
    "0x1208792af32377cd04bf0b77947ef589d4069b8743bc8b4878d09daa669b6b9b",
    "0x0c8593f0fd900eba22c520adca2fac43ef1e22676c396804a421cb9b10ec78a4",
    "0x1bd21887ff52ef7fc2535b98dc27cf269baa0905b006bc8c347518da237c0eba",
    "0x1f286d70c425a4f9c587777c055274940a860def2ee096dd382b3098b526a211",
    "0x12f295cba6747661e15782c98dfc37986ff39910b5ade0af270359a0240ac15c",
    "0x27b574790203bde222f06ec565eeb97b5cb638d48b91d696406ad922c5cef4aa",
    "0x0b48c200ed9b9c2e06ccf0b4bf7879aa04a4f3c96a123c76b141014cf1cf3db7",
    "0x102542507dd3efd2985a8c1f32b693db8bbdb68915ddfcde0495319274cb805e",
    "0x179ecf51290f06d865c9a5f2b0e0c0d8538f1e0cd827aeebc17a52243892961a",
    "0x095495252df2a4b0436c4ed7475418d3ddbceeedefa21c93f869d2ef7af8d0e7",
    "0x0199f70bfee188c09adc670d87ab0faf853a05009f4bf5f02ccc1118ebddfd04",
    "0x2c4424651e6612ac440f1a0337c11ab8de4e454b02e541f0d9fd94c71fe8894e",
    "0x1026a6b199faf95f5d25039aa4ac197858efccc396d022ef2a91b6e8daefd401",
    "0x1592410f12e9ed7cb9a4e179545bb25e1ccd1fe651a357384c25c4069c91f447",
    "0x2eb2a6361decccd18af7220bf07acaba1aa2f72df3c8987f2de50550e2958ec1",
    "0x004e18672f832f967bc48680deea67cfaa5239523c8300431b3a5d6841c6c83a",
    "0x15d58a38461f1a3ff4fa48c05893549ccc347de223c3defa6b62ad235f8f273c",
    "0x2f8b363cb00ed6b4c59cdccdd8bc00c2b74a20692f50684554d26aded7e536fe",
    "0x29723a5dce93cca5d1b5fa130caa23df1a0dc60d1b04a5af92cee4f9725c35c7",
    "0x2c54d95a6a6f7e09e4c3562ecf6d09641e29a72cc7a46e97555232044a6a8aaa",
    "0x2a62c847a7404e47d198158bc9783f57a7e9e936a512ebdb6ed07ed81040f9d1",
    "0x1276cfc056c55b3a9feb8734289c38bb99f2d4adb5df85b9c6baff7f42489ddc",
    "0x27074fb9a068da4dc423e47f968c2967012a8238c74008a2d3cfae739a454417",
    "0x13b3cc235d66d3f0db7862ee5b3e78a7ae3fbcb379571af077693fa3a318baf6",
    "0x1d4f5cbb8ed933063b61afb45c92a6e42cb80baac351ddd75efd8ada23535e31",
    "0x2d4a0453f7e3632194d15444457f033b28822ac9e46aa9e8141ec98968666229",
    "0x0996408db77890304cec004cff24e7031f20d91245bf698b8d85185ba4c6ca3c",
    "0x154c4433d7bc73b4bcbd880f933fd7ae87e618b381b3529bcffc2281cbb1ba7f",
    "0x0dfe738c2dfa783eeb594adf67c5e2b5581de47f8c9cfa8a37fffde204eeb4fd",
    "0x009517fcab532346f0c8b3dbce4a6b24e901772bd3bfb55dd4f4cc1886be22cb",
    "0x0e87f69b7ba84abd34fb9822c91cc4053914904860eb136b5f24dc56c7ea4ef2",
    "0x20f6ebe7f3b318d178af7fb4ebfe5e71b5d3380ee0ce07f275051f52fbce3d50",
    "0x1f93934dc4dd378c4ef0c106dd721e55d59db5910d92cc721dbd1b71e8b16ac9",
    "0x1c9601af9f45092f62ed342e62ce154a3ee2583025f089235ced1ae2f1f84f9d",
    "0x04dd1e6797a385c12d4b7f911a28ac12149e3ebbe1ad536870725a7b494b13b0",
    "0x23e7a5d59830db614d16a0ed4eeaeaee5b793aa39af8ff56aa7ca3bfefcdefba",
    "0x12f8f2d6c41e9d384e01d138695acff6a73b557f5d2606e598cb0ffec69f091d",
    "0x01376653f8bcf8fcec5ed8c851453e6bdc678f31fc9c8b94453230e99068d2b7",
    "0x26b0bf23169407407b4c3b437d920b74c7ba13058818edcbe4eed125540eea78",
    "0x03a8a2797f6d8244e383f51fdc0edc69873d81d75b6ac0b92643e4b02f67113d",
    "0x0758e495264cace99acef218843149d62c2de064a62936ad4161a862198b697f",
    "0x1973c04a42a8996d5f38671e71d3be5778de8bd4854259e8bb461ffc56399278",
    "0x2ff27debeb99ece34cb68ad054c3725eb8ee3857dc97961896e1691a1e76a6e5",
    "0x1b2316eab766bda304543e47474aef9ce91830a717686d5f74891d25eda9e3d2",
    "0x29186c9e4543d1e838518a836cd160fea11d0399d40d4a44248b5b86773454d3",
    "0x2fb5e09aaf4fb0f3e29d8037046242dfcfc25e0acb6942d709f339c80d62156f",
    "0x2d026814a08dc4497c6e249debdf0be4584d75fc1565dccb36549687fcdce5f7",
    "0x1f530540f99193b2535359650505dcdbabd5dae0e7a25029eb427da77dfd29d5",
    "0x059f1ad84cfaf236838c5dd78cf530e0f008631d7b911b108f9e9e35927a6a0c",
    "0x0f0cb8516e7358e13f8d29e3d7ca3b8772da3f34c38dd54b79f32a64d3a173a9",
    "0x0a7b0e2f1fa2d3b05d30ba4010d38a04a413e0b31aefd44a62cfd75bdefaacb9",
    "0x29785cee4a463f7c6a9d0faf92b5d7835e2cf7ed758ece279a896d3165f06e2a",
    "0x0550c951520a57c7ea1253ce4198f5151aaa801da0c49b6b1599e1c4e9cd4a41",
    "0x0e4f3013a99a670d3b60456f721932b60627daa3be8aedfe7e4d84d5528d5a94",
    "0x116159f5f5be7755a0d02232fed8d99f2bcf672536c1373bcbddc83cfe7fa461",
    "0x05f3b1526b9d0dcaec2d707ac31e87e8699a46c852ac9ef94abd5767de5cff47",
    "0x095e04894544e210764ff538802121e800b39970585063fe611136276aa16fe5",
    "0x2ade487b239c12bb48ff17f278758dca8dd1278972daef778f4c118dec3dcf39",
    "0x053e3aa1aba2476edb26d2463332a0e186ed428adeee869d822401930f9e4128",
    "0x2df9eb23269d857b49c76080928a62e518402ec26aeace0c0d88790830e5e23f",
    "0x224883469ecba978372e4e9412c3a434b7058d9d76f1d1869ca187ba7c1590d5",
    "0x0e0dba4c312b41bb89edcff913835681a106d97ea723735220c2cd806f16968b",
    "0x2d9ce08f05ffc1eced293bd9f8fb89d7bef456b2b0fec016e795c4159325337b",
    "0x162b649549c5adc5f781e37b7df61e7ce65f084b9825a23d9b6aa4bdc248e998",
    "0x2323a160c2346980dabf302e69e2cd88f307c1741dd583d36a06733f0a0936c8",
    "0x047d629034c42906bff290342b2bafa612f08b0f888fd5c5ea02384c639adb87",
    "0x16749375afac68bb87291b6167aa55e389e69932dacacbf3762fea925d7ee5c1",
    "0x14f633ba5f21231117f4d938bdba1ad6587f37312dd852ae22e508b2557524f9",
    "0x2d02f2b341f65ad9d99e89cba23a797806168efeb2da8169f7893783c9acb782",
    "0x25f565e2ea7cb2faff221c35deec04b825960e1b26edd936b39fd2c55a48bffa",
    "0x0febd4fef89c49b6b12c353e3efb358203aef5f13e2e25cdc88a9fae17a48ba9",
    "0x11d001a9456099cd86c95cdef6bfda0434d6f52394944335cd6513bb41add7c3",
    "0x1cc2b66fcd7d66e5ff81955bed3ce8d976aae481f100e40a5078171cfad690b4",
    "0x16a755dc1ad34b4562a9d57dd375ba68bbe5424df505a5df3d1d1c16fc6f516e",
    "0x1c6d0e7f77d871f89f0324dad2cf370292f81cd8d567129b56384ebe8f14b078",
    "0x278006a7fd3b154b9f25be54a013734b0a5372ff88377c26eb219039558a281d",
    "0x22eb2867a539a9b6ff51d4a48b4cd8419252d07c0665d0baf82acf8aef7de8ad",
    "0x1a128b7188d4e3f1c22aa4bc4525bb26b50ebd80f50f267988bfe2e466e56a94",
    "0x1d2faa5c28aa1d533513cba89750b93ce71b4510c4c215eb1974a59051c5b093",
    "0x28eb1c41a050dc8aa3f9a8037cb81f575e5b1acadc49e886e90bee7f1a485149",
    "0x1e2586cbca2364027ac96ad1490271b866e723385e96c9f720a72b1f67078e6e",
    "0x13c7e5c7724e33d7acec9e42ff8a4ee4f1ac8b6d0038f0faf4908e74ed06c9ba",
    "0x09bf059ab4925c39c6df84371572785d35e40be573fdf1be914ff6a87066923e",
    "0x1b7375f3920e121871cbc71e92a2f47518d26a20f236f9194a5c48f86dfabd38",
    "0x1494848f10672e535de527d6d0591019987f6e11ba33b6f6eb73dc59289c2e36",
    "0x195378dcafdea646a00ae78d9e30487a41aa8b8864ef4035a751c3b8ece36b0c",
    "0x0b6a5c76a2a2a0db3843ef11176411388025f380e7a2d7ef1a6acafda5899b0e",
    "0x0823e1d157f7c4712b4988af4a0396edb0950b1ccd001692e4eff681e14c2fef",
    "0x1633b048d2f14628309dbdf5a52736c0c5de9bf96d7fb9d13a2cb4562074b222",
    "0x1f77ddd90f1eab23737895ec06a295467086513dec30b69738d226c82ed5e430",
    "0x09c71939b3672bf6aaaebcf3717dab67765d8b94726c19d76d57e7aec751b94f",
    "0x048139270f0ef8f68d0b07c5d0005d7ad91d41fe306c8587bcf32d742ca1937d",
    "0x003adfb1444cbf59321984d74e4434f3ed8a2f2376a41f5b9f52b1a6172c03e5",
    "0x2eec4a7de823bf9531d3f842e9a9c74b0d0c4f8b56a5a25ede19b11f868b89ce",
    "0x0ea574b644b9f4cba43338122827d08f07484a4ceb24ac9d00c4a668838900af",
    "0x054da055cd915cca9a0da4dd2cc86d99f08b287bba925305ecc28ed0bdd28990",
    "0x02965a1d1f26fcd147af96711976f84bc3f08a50e8b8c38f7e83e8638b8f4706",
    "0x1f97b34b9622f33893182c89f86ef052ce8e46a3bfe2e33fa2a34c5e051d91b8",
    "0x09a063b0b5ea468d93edeecfc089699f815eddbeb5e9369046740c7fea6d1cb5",
    "0x1242820c24afd7cc595f7a3dd0534c6cf1f00c6a84291c65417397c07d46b778",
    "0x2983c402aec15b1d15f86a8d0378769832f0d5ed57aab1d11cc08b4509512da6",
    "0x136371a4b44febffc233bd009ba8673764d2a73512e0eab44024cb97134a3dd8",
    "0x2970729690bd8c8362bf5d0a76c215a03c26ef8a3e01eb91cb0e0c70ee25525e",
    "0x1c395ca2c5db9b254b9b0ef75ba5c0961750f646f9a6a68d60e33ca2ce84427d",
    "0x02356c76528c4b9ae14f13f529206cce462782256984db7e1c3aad5d6f367f68",
    "0x0c5a67378876463bdb3ff94d63e062ecef7bd040316eae92c8b035f693ec388e",
    "0x1b2aafe5f720bfc99ef31b5e48b35df72fcc920e66c3d90d86537ae35ce6bff5",
    "0x067987b7638b9b082848f8eba41ee203d3e90fc591407a4d87f81f088f9612a5",
    "0x148d4b0218744bcaccceb62b6313a57272a1545fd75d1a8ebbd736e4276d5e6d",
    "0x043f8986cc56fcf8e88680a1e8f1c247165bcdb9a6ca2d94c7418d10ad8ef847",
    "0x1ef035d9ff4391c8001fbec565a65ca3cd3b7d0823bb062a9141503a79731f81",
    "0x0a5162e6b35a320dec11ba8639a1192f6a0a464f84dd3899c4dab9d4ebbfe024",
    "0x2b5c89e9872aed76baa36b83f87eb830fe16d34169f9eb1628e6fbeaa940cf3b",
    "0x0625c126499750374f2d3fd08940d1c0238fbd8da85bdf47928188e3f9010627",
    "0x116bb85cfe6730c6448192438af1748221d2bb302b3258350cbebb1c5eccd965",
    "0x11aa65a2b09da598bb66377e54458c1dc4a7a3775f9c9cf51b2ebea5c871abfb",
    "0x280fbd8eb1ccc50603dbc78eb0bf9cb903cd9df30f0f25f215ad4c3e1fb6baf5",
    "0x0761a3e812087679e2748d24993af14664667aa3d713796c79507f2a63f8ed76",
    "0x2ba668f10abf878c8010155d539eb3cc30bb698f0062b1ed338c526fd12ac96d",
    "0x2f4e05914ef7c1b2edf41c51266d3dc3e75c91b4c8dcefef873287120021ce0c",
    "0x29274bd37d7863d5ec7a82f28bce6cf183fffd4f8176ad07b158f1df83c64804",
    "0x0c48fad80901003d9b0da5451971f8eee03e4c394ec29da5bf20a7bfad98e41b",
    "0x16cf2cf2b9da985924e713d6559192ca6128ccf71b4fc7c7ee0142d1c32f20d9",
    "0x00b7d9233273de8b110605a3a7820c13cf7019bacf7e5882a85d5689f15c8cc1",
    "0x0f291f5ae7e99aabc73894608962de3b6b76490754c0861de32a58b1cdb86e18",
    "0x253406b596a33f5cf4b7e83f26116eb40d9707911b4290b2af400d58d92cf210",
    "0x0812a4144d0d74bead1c5710d5239b640ccfc39fb66dab8eaf7cb3160fe35861",
    "0x2d81a6da9eebc5d5d239d13b961bdeebadcce19f0625de11a866bbcd0ef6f174",
    "0x1a22dafad979cab2f645899290eb4daccd04feef3155d88567324d23646f5064",
    "0x1bff73ae8dcaec7d09db8cdaf9ca7a9a5d685a1665855b0fd4ab9c15289f181a",
    "0x0a16f8b0834ada0c92b57e0f3e79e31f4bc6c4fbfe1e1c8a22cce904c33ee709",
    "0x0ce7964c214c6389d581357e69009a141e16451def5e801d313bad966d99548e",
    "0x2825c06bf975dfd5e8466bee81947fc45b6a3e704dfe0350a04a9ed19293b3e0",
    "0x265917cf756c617609b958a33522fbaad9bdef1dfde2da8fc4d33b067058283f",
    "0x305a6987d779fbb9c92aad8c64fd4398a501b347cf24d3ac0374379c3b988e0c",
    "0x19ba5a328c09be61df3216db8ccfca1392a45d45ef73c6d0bbdf798f52b0caea",
    "0x0569057f32180f19cf467121a3ff492228542300b440840ead6ed63ff96fc92e",
    "0x300ade0e02d409aa9cbd650c5018bf52c8aa6b46c3523664404942451cdfd7f3",
    "0x13e7afc3e5b8ae05421d3101c6dcd069e9730f8b9a4d28b707919627d82ed576",
    "0x302cebb80f47bc0d048b047e3ec4370a824d7741209189d6fafb2e923c95f674",
    "0x0fec1e8606f9c19f09f3f6cbca8690f2a82c728121731c10b70a0a27425b7617",
    "0x01b36c8b38abe36f31c85dfa0a4223c2127f9e70d6cb00acca7b4b820c42b4f8",
    "0x1ae800dfd62a6f893226eaf46ed30630be2e658ca33bb2f8cb64a0ef6936167e",
    "0x043f80240127ebfdfe64478e6b490c262943c0891c090e4f9e5da3a777397962",
    "0x284cc004329f4e38c3ca0e7b3148a180f6769757d97698a510f153ed07c0618b",
    "0x0a18cfea20c4b70b9cfafbd495e4fb978527dd3adcbb2a1b51338f37b58eef02",
    "0x1bc11b2f6acc89e45bfc09641d1f50fe735abfd0fe6b4485e134afe45ad302a4",
    "0x27af048a94639f26777e999118a6a53c031cc694291d09c52dc41cfbf548c07f",
    "0x226ab5b34d54c58d1b8fdfa18c3718e0adb3382accc596eaaa90c06d43d6e8fd",
    "0x2434cc868807d7dc6385a67ab520f6908cd692288595b76156d7b1191d024617",
    "0x05f662504bc7e177ef21ed6b4d8ef9a3dce1e82b88b2d48c35c0e23b405a15cf",
];

// compressed_round_constants
// const C2: [&str; T * N_ROUNDS_F + N_ROUNDS_P] = [
//   "0x1051abd795bb781c5bcb3d4c7320b88f033cb1904c5b8559bf08995be4d6305d",
//   "0x2680c4e5e102394a8c53c7ca99003cbeb3422caedbfa62c2373862e367a3dd00",
//   "0x132e8252ba372e32578a441ca6b0865f73d890c968dd8b7642f5b483676160b6",
//   "0x20719ae6d90715b480905eb82300c86b79f9a27096e5a2434bc3b5c61e49325b",
//   "0x11b4ac9ee8835ecd48324043e167301b11287e217863c2309ce6310ba43a2869",
//   "0x26247d3a9e3a6a24dfab7b5a44b88cee623fd5bd7175f97b0f82f4f12d900a69",
//   "0x0d80d2231a9358cc52c38b9b48fb6b24965e9facaa43fab1d3812126087dcaf5",
//   "0x1ebf08542033bcb8167da60c6da0fbe84d400ff14690637eca52f5051b55ee4b",
//   "0x08089ee8cb60c1dc4be31ab8a7aa4bb03116f71a0124c957eefac76c536b8441",
//   "0x19ef65c26e83642b76f5f8d08ff0a6c884c806ec83a5e4a43a11fcf480aaedbb",
//   "0x17c982194a6b7c28f59b6c3517a7f5ca5da89d84aacb975ec78372e737a71a02",
//   "0x236d418b056b10ac5d87cdec7408c8f2bff989e2e2b311edc4cf477131c18600",
//   "0x21307c774d1cbd79a39372713047356b2d7e4fc295ffa9bc9a1561928a07aad2",
//   "0x05ebd402a091f9d0f52ab2e245740fb33c79d8494f1970e38979d9fa59ab39c3",
//   "0x1bb5f47bde76eb8f7c9b6b4b15cf2fc7d9ed4a276c356afd6360a07c500185ed",
//   "0x167761f9cdb874fb2d6ecfe75e5496a310c0cf0195cff7d6982034efa8e68fc7",
//   "0x2e2a58c9b0f7e071c814b5efa81911f332b47194d20ebb09e12b9952f3080656",
//   "0x2efb296424a9cb0e31ce116f37d0c2958a3bc05b8f54ad05b5f985fb003178a1",
//   "0x226572d04d4e2b4c2a95f92e1e335dad9505df2ee2144998470540c058f0ebf3",
//   "0x2d4f75e1bd2eb3c03a2b594aa22ee2c6f134b8a2ced7ba19ddd7f0dcd6dac466",
//   "0x1968153301264502ecf0c2d14b25d57974433093a16d100b624da4d89da24b7a",
//   "0x1b4fcceb1b7867fd6ac2a78985105325474f731532e11cc7774e08f2a0a1f552",
//   "0x2ea3b049ab0b5a9ebf311ccd537cc1b97061f88f5e6fb1d89892c2ea9922ed93",
//   "0x283341627b89c2b4195e4e3deccb1fa9667abd5ae0384890978b8c2f2303ca52",
//   "0x073501697c75f94c6280700a344b65261bebfa2d65aa015a2951cca5e4454b83",
//   "0x0e4ab6a521eba213d8298f3fb05f5329b0a354f1f2f2cf679f02626c3b31e5f1",
//   "0x0bdd976d1f9de966a5b50b680bc3fc80851a04b2d7818793066b16252b046a0a",
//   "0x0148cfe3300d5a846fc99180588d44df5318862f961d42810e33ecf54389e918",
//   "0x0beb79d8f8f1ec94c21e5fe3998c088c5f9a52d84301ad37014642cc12ddc237",
//   "0x183d7cb7309d7932aa3b44e25cf5c22aece6cd14a214e517c9efcf2a90ef172c",
//   "0x2aa370f3c839a1320df99851c6b08db4c1b20160aedbdb25f824af696bf3e7df",
//   "0x2c78fcf1822620bb6fa71e7873f35f1307c7a20959553e636a6165fd702d8a15",
//   "0x1f430a3a1ea125ad9629d5c70f6ec6af30a2e6d6ef2462eabb3653e81048edf6",
//   "0x28e1fea385f2a2842ecbca27367b2588448459f66565647a39fc3e246456f090",
//   "0x0208a9b89880924585ddc1d4a04f74c7002229439e1ade59120c9ab13840ff44",
//   "0x2eda4ad42af1334fc67debffa05b47391a866e262b4c835f08dad64915a2ade2",
//   "0x1e80d79d695ee27ae62f7d7707b73ecf616ed5138cf511afcec53f4c16dabf10",
//   "0x25f924ae0ecaa669d1e06b5b64b499b955ef8692f0ffeaecd2f262d332b39320",
//   "0x2506b81886426c956eed0e21f3d7c08df0cd1ebd6429cc82519769d2fdf6ca81",
//   "0x1d02ab934fd1da987bb67fcd264abb2be080b4c043ea2102883add7083aea687",
//   "0x2f68b7101b9be0c15ae1f69e4a5c97c000b4f50dd6307a102612f1df4ab2f157",
//   "0x0e413bfe128d484357edddfa52302f4ae818217edcfc13a90d83a88962063137",
//   "0x036f3db47e9af99d894c0076ffdb80c0e1773c050dd43bf275260b4beed376b1",
//   "0x1416cf83e542cf80f50f4f4420053c09362e02cf0e5e4d75e0d29182f562c563",
//   "0x1d619bae5fe1569c73efa35ef23003b355fa72da1dc59e6809a058073f81f105",
//   "0x001a23943a9025596eb585b54131cadc108962496a5920d2b39f2d5a286efe13",
//   "0x2a4da67ae5ae7ea86a4616abe6436412a1a39f49505f0c713c4b3fbbde99738e",
//   "0x122c192f2d6544862f2622a898af93d8f39af892c72f3ddba5824183a4e3ccc4",
//   "0x248e0115f54c60d6aa619921bb3eb835804bd543c15303bb69d4ed58d6dfd62a",
//   "0x18ffd60629a23ad3880b6325f6ec2ea8f60a1c80e6d0f35088a1726655d3b8f8",
//   "0x1bb10e4c4817994ed2ef0a48d13c74e3ff8779b934c8dc6cce33d570723c698c",
//   "0x26a2894f2b8960ffe02dfd4d7a6b69be79b7496a2f0a36af7612dc798a9488d7",
//   "0x221677b22512763542ed1b13042b0a6ceef049890ad075e48cd086c972b3bad9",
//   "0x11bc1986bf8fd50d87e70bede0d8245fca14aa9e49fb90a3855b43633c525234",
//   "0x19d79a284acb7223899c109b2945309553a3324eedec978c5bbc5d6acc904961",
//   "0x0f8f995ea04e61e62b878d0dd9681640945f38897f0f05772e8f381535794603",
//   "0x16052922cd397c1b8356449553a69c71af1ea4af571cd0db105b1df4fee09b45",
//   "0x1d5553fea1257176b2f0a6d453632e889d3cf96d64fb75ba9eb1afd62b94d8d9",
//   "0x153cb244d2485429c20c7d591916282609cd32a533177b4f960500d282c615a5",
//   "0x1405c65136811b75d97e51325b50a6730b209db1b7a728c752c6557e7ae4682d",
//   "0x0541c72f476deacec17dbd7c081ae13f252114b80498db1d91239e8a6e2bd480",
//   "0x2a3370091c2221df2f115a1d222144b767c28bd854f48ecb9ed9addba09b597d",
//   "0x2d4641187d6e5c559bd3682896e3c1641e2ff876f6286182d3dce3341a5f03f2",
//   "0x087575bf2e6e897676003a50da7df3b353660f86244d7d5afc286faad8135f0e",
//   "0x087283661e94a1de5e3c0c22b23472458992f2679b2402fda5e8195f05d823e2",
//   "0x07f186982b6f16d4bbb149153c94d35bd9088435dcf25a95f35892f953354188",
//   "0x1389e0820016da62c7f5284e3a864e1c47c4b68f98a1d3570a39aa0e7fa8722d",
//   "0x247688f44fa8c70de6d071e040ca14a4ce84d375d1b5ca34ce49d0ce4c4c3eb7",
//   "0x290150267e2f107cded65854a69ed25826ea8ce586f664813f2d7d9fcbda0f0f",
//   "0x20aeb059bc5e5bdd90ca5bb6a77ea21737b7553dc00ff8c68d4bad85625b014c",
//   "0x15b7876d22c8a7c9a068c09e6202bfa037ef43b6e4a9f697026eb37778c3a8ce",
//   "0x1b9f55d7813f86e64c0405014e1862c0773284c732b6c02a1daf90f2fe4e5b19",
//   "0x1b83bc85bfbbca9ec6281b33aeb061dce68876b4585fb494078f0c31e83bba94",
//   "0x0235f26eb164f92e49dadc521183f9c543b76d03730bc8d657355b1f06b48613",
//   "0x2b00ffc6dd7b46e02fbf1c4f7623a3d7c13f3630192b97985854faf73292612f",
//   "0x1d56cbf7bae51373f9b2222e5dbc147a5582dc457668c56733d2c8077566d21b",
//   "0x1dd534a1cae81a1fa8535c08270bdfbd2545db42d9baa32b6b1209e5f18c4c89",
//   "0x2dfb0f42dc4832ee85ed5a97a7325f6dc03e90fcd69a0fc49aa9241a670e7e59",
//   "0x2cb94104bf4b6dd13d0fa125dfb580b82552800c5601b55aaf6ec8d9c6769a1d",
// ];

/// mds_matrices
/// https://github.com/filecoin-project/neptune
const M: [[&str; T]; T] = [
    [
        "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
        "0x244b3ad628e5381f4a3c3448e1210245de26ee365b4b146cf2e9782ef4000001",
        "0x135b52945a13d9aa49b9b57c33cd568ba9ae5ce9ca4a2d06e7f3fbd4c6666667",
    ],
    [
        "0x244b3ad628e5381f4a3c3448e1210245de26ee365b4b146cf2e9782ef4000001",
        "0x135b52945a13d9aa49b9b57c33cd568ba9ae5ce9ca4a2d06e7f3fbd4c6666667",
        "0x285396b510feb022c442e4c2c1411ef84c2b4191bac53323b891a1fb48000001",
    ],
    [
        "0x135b52945a13d9aa49b9b57c33cd568ba9ae5ce9ca4a2d06e7f3fbd4c6666667",
        "0x285396b510feb022c442e4c2c1411ef84c2b4191bac53323b891a1fb48000001",
        "0x06e9c21069503b73ac9dc0d0edede80d4ee2d80a5a8834a709b290cbfdb6db6e",
    ],
];

// const PRE_SPARSE_MATRIX: [[&str; T]; T] = [
//   [
//     "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//     "0x1abb62ca4c14b671601d0fa5ef8caede54af9dea1bc359143ecd6c52cf1bb49b",
//     "0x1bbb53d50eb838bcdf6a1676ddd85c6f4f4fe1be7a543766d750c18437a77821",
//   ],
//   [
//     "0x244b3ad628e5381f4a3c3448e1210245de26ee365b4b146cf2e9782ef4000001",
//     "0x24e8df187b37511fa98859bee8bf4d0db6ba3b98d2523e938acf4ae32e312a79",
//     "0x07bcc2fc266d385555bc62a990474d9c60630d8fda4782684a606f1c0269ce4a",
//   ],
//   [
//     "0x135b52945a13d9aa49b9b57c33cd568ba9ae5ce9ca4a2d06e7f3fbd4c6666667",
//     "0x07bcc2fc266d385555bc62a990474d9c60630d8fda4782684a606f1c0269ce4a",
//     "0x0274ddb85db6be9dd880b9a670ce32e4063ba59e461ef3c72ec1f8710bfe42d4",
//   ],
// ];

// #[derive(Debug, Clone, PartialEq)]
// pub struct SparseMatrix<'a> {
//   pub w_hat: [&'a str; T],
//   pub v_rest: [&'a str; T - 1],
// }

// const SPARSE_MATRICES: [SparseMatrix; N_ROUNDS_P] = [
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x07c9a81bd11f83c76003526f376c58a7e7852874566f2c161de8b3b3a8068a2b",
//       "0x1b500feb0c2b15f5512b2da68fb25f0c588f54de28646184e9214cfcaf0bc420",
//     ],
//     v_rest: [
//       "0x045120e3e483e0346dfe4b23130b60a8c835e84d287b6bca19ba90e6a81a71ff",
//       "0x13b6e73772ecac5aebcfa6edb56de10034e54588545f26bd0244c60aa420193a",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x163d82b0e5d9c256226f6b10f8de834b3965f4bada3193ed2154be5d397233ca",
//       "0x2fd4a673097413e9071cad1a58ff029462d865978b9990d398f299abfc3fb925",
//     ],
//     v_rest: [
//       "0x186ee829fa260db04c68f591f93b8dfa6005d03c896ecac6ca8c93e7304375fe",
//       "0x2cf93064a9b4d0f723c8150cfbe48b8bcca39368614c372c1e65764cd9e75197",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0ace88991f8182b6ac986323d5e3c268eff275de5872a96ffbc2eab2e9439826",
//       "0x2d1af1c91dd8529696992582dbd6aab383a438a583105f45e445fd79653a9cfd",
//     ],
//     v_rest: [
//       "0x22b5b80f09c8e656f897fdd7ba7299932331c4aabe707d2a534aad309fae0923",
//       "0x0829f73741f663cc62b86bc8c172b7a6924c24da2d6bafb9d3945608e85d85c8",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x18324a15ced5607d59501564cb9a443dc97508d543847e34065cd60f100ec121",
//       "0x2d1d5cb259a98953beb59423b8029a96aec2d8e7bb28d4f2f219b119c79fd45c",
//     ],
//     v_rest: [
//       "0x20e81f82f61ce855da6cbdb35c7c3af921acaac06c63f68d57bcfc2379a6ae2f",
//       "0x2af3c4f8c9de7b9cbb098d5c9efd6cef423ad99051af3c0dd9f82edeef4c3297",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x19434cc941297f9004ee5a39b6b93efa0bdf52cb005b49aef7753d0417aea7e3",
//       "0x001ba74172d5b83c7c89e537efb539306ee12ba2d50c8f24a14a579741194ab7",
//     ],
//     v_rest: [
//       "0x005230b7c03a003a3ab0d9c2fbcc3231661ba907a2e63c55dbc83b0d3cb0f96e",
//       "0x2a33879273c90ad1571dc1022b233e0b02118191748bb04b60aa901ec446e9c6",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x105cac78a1844c85f3f2fbb6eab6c45859f7e7a1732e8da8dc366db40351d02a",
//       "0x17d025f7de08c5bdb8a50f0c3e4273627d8510873149c832866d6de4747c26a8",
//     ],
//     v_rest: [
//       "0x02d4d0bc472526e0d7025911ba9f37eeadfdb3937921d5cf7f83e33e4a439da2",
//       "0x11e2af9a861012c6a7dbfec5a10aa6fc0a57153370ba30110f3a4d730ca181d2",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x175f31e7bb0a54951e1187d2647ce07cdefb31b5616d055a9d576083ec9c8569",
//       "0x2affb345e637048e2ae4db1f18c7748857f010cd0f5c89f9a8941a0ac80d15ef",
//     ],
//     v_rest: [
//       "0x2c538e23de1e7a36708226d38391d1d088bc92bf0850ce7d32ed7ab79b0e57e8",
//       "0x29391dc33bd68a13438bf0f6f774e132e362f9038f92bf2f2c9715ec83847b84",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x1a5bbf64fe44ca4208b9327714698e0760e9d26d431897b41cbabf2ef687e29b",
//       "0x300f65a9589e498ae5198b30cf6013df32d6780cd9b117b730c911b66e4cb7d9",
//     ],
//     v_rest: [
//       "0x2fc61fcc49590ceb7f6bb7d31b3af856f87185a5344df3d83547b0c033687ce7",
//       "0x0f0ff4e357ebe6b85c175bea8851f9063646c8920c3b2340487fcf7da4a5798a",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0bab2c12fe6237e73b625ab377a958816fd94ff371e90d79720398783327f6a1",
//       "0x2efa00b4ac7d9025429ab75e7a84e1d3969caee804202cb5b1abc55e519b8315",
//     ],
//     v_rest: [
//       "0x105526e2ed63c01969755a32a9a1ad4c930bd0a57d2b49bc4ab4a15a15ba1ec8",
//       "0x05ba8219db2c39520114d0a91c7ef1b6e2b5dac478b6651eddde018fd72d2edb",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x1f2208cb28ad023577e9d771a8bcdda140e49a54a18cdd0f1ea16589ffd51c82",
//       "0x0e6aa92aa6fd8c67af73193b0a326a4b149005031bf85f2d347715e3e1847ee1",
//     ],
//     v_rest: [
//       "0x2b29e4a4561326e51076b8f230dc7d14ec087d48587681363eff981ef3cd34d7",
//       "0x2e330a25f5d91eb8cb64d8da258e467f23d64d8a1e7585c2416f77f75dccdfae",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x1d996214b8c03b1cfc8f671a53085bcc994b267da684dbc9819e93709e9e9251",
//       "0x107740f4b125efe2b7c6b4ca54b938c389385f1029ea78a4a5b879af2954ec36",
//     ],
//     v_rest: [
//       "0x0342b25c091d2bfd874b0bdbc887ecf8d848c6e43be4b77d3994ebf5fa39aa98",
//       "0x0d1c30c6c6be2d5d8d43514813677eb4553e779c37155ea5ae47767ba756d6b5",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0be3e7f0517ce09d4c5cbfeee318192d96135a3a4178adf817efa88a614777d5",
//       "0x13f5a1fb5ab2748b93188c81da561c44256538736018f7eb576ff6771c268f77",
//     ],
//     v_rest: [
//       "0x0b672fd8f63adedaa5a7ea7dd869376a370d8f1252e229ac74cee285db4fd293",
//       "0x05e127f0a8cec95131c594294917b1bc02d797436a4ce7ba008544bcd62d6946",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x1aaca71ccdcc38f377a85c037053c11ab5ab3bd7e2eca78f41d7b533e68c2fe1",
//       "0x2d28da99687c3b8ddfe82503370e64281b4921d07e13bcb1bcdbdb2f8cff2260",
//     ],
//     v_rest: [
//       "0x2b95f9f494a98a8620f8fb361c75a4a1dd6fff0d78582d99760589f782dfb3e0",
//       "0x066fe372e5f23fa9c8b4a9f4099d0edb9ef3c6b5aef14668bb3f120fbd38e465",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x09a2a7069a7e821ae4296941db46427d4855a4408f9db974db51c97760468f4e",
//       "0x008705b2dc661a587a25ed4dbbc9a1a6fb15c4a60b76559e545c1514504800b3",
//     ],
//     v_rest: [
//       "0x092a1b960683573210d8ba54562d50e4439abe7f650361f3d9e1a5af2c9f1e20",
//       "0x123ca879a1a0a286d683b50d08eb6c2d51b9edf5aa2c7fbadf3c409b287f4648",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x20a9c2f8f463592e8c0e3e163f4e6034271c07f01664721ed3d97a8a056f721d",
//       "0x2fc4c8e37d6b5075cea1e9a56b79089dd636a0e168ee1659038a5db5f9fdaa46",
//     ],
//     v_rest: [
//       "0x2ddf4a5a757ec416fec505668bfc040fb79c7b134d32524445d5a0794779879e",
//       "0x099e5bfb60b90cb2be9e657043c825595aef11c0803032b56ea9ec40b2c27869",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x2ec15aa44ad7e7e36c868c80170b24eb5fed0c96f82edd0f71d0a9b6289e6ef0",
//       "0x1fdae92328157fc1dae4a9777f15c138c1954ba89953254ca6e8ce5a980c2540",
//     ],
//     v_rest: [
//       "0x2af199f4ac8560ae9c75bac21258092c67f5d56c431ff68a61d63e3b9dec9476",
//       "0x0119361be60ddd5eed05ff9d4491dd494b2eb5d7b518f324288adb4e05bd4855",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0b6f22b0203c85cb033bab29e67d3b4bec8090b5764699db83639a5cde43d821",
//       "0x27fee96e3d8c8e5357a1e9bf7861299554e6b01db59608f8e9fc030c072854c4",
//     ],
//     v_rest: [
//       "0x2edaac0b1e8e09ceb391b1a8be6fc50f3d4f29936a742e40b2ce20ebf5130ca4",
//       "0x118c6ffa2852d7b44a15b5a603d1c796270528c54473b0c8a5b3757eca416b95",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x1c4f3c27d12ed8f1d8fa3a68c2c360cd5610a8463bf14d4b3a4b819c8da55b7d",
//       "0x18e6f3e86ac8455b1e1f448816a02f61bbcf043c5f38c32098b61058511d426b",
//     ],
//     v_rest: [
//       "0x062714a232eaa378ede7389930fd01e1b58ede1619cc6949cf38c14487baa2b4",
//       "0x02bf6b6326be5c2a42f992d833677a0fb4d9a6f74fb553fe226c17f90ec58894",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0b6ce1f6cbac66f4257e33070ce837cd87301909753fe6eea75fa4d5183f8c4d",
//       "0x096d8a2a92e8a5b0390b82e632f77a87bc6aba8ff5eb9926f062d4a422d0805b",
//     ],
//     v_rest: [
//       "0x2e895a3938e314bb22b69d3b37f5be2dbbe21dd5ffbcbbc0d068a219f1305d1e",
//       "0x1d76c461ce6dc2852213a96cfde2190a21b0f8ff7b3b06fe585287766358fa15",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x18d37fd0a2cdb157bebdf16e5442f08a3acb80394a84676ca2b02ed2e195dc1f",
//       "0x02194fe96e85ee287dd1b8055596372d550feea09b64d829e1310f6e4c718526",
//     ],
//     v_rest: [
//       "0x0b848dcf13e7db090e2951265194a57866b0e42754af7d652726b01ee70453b1",
//       "0x17705153a444218758eb24a4ccbc8e49bca817d0d1c76a01f9a86092e1e9ca41",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x28cd68f1ad74eb47f57b4658869ee0811dd16bc1c6556920d5b7844b2e1fd349",
//       "0x2f11844de51e15d18afe3ce4b0edfdd11ae434da3e9d2baa589c3196c0e6256d",
//     ],
//     v_rest: [
//       "0x062f137725926af47ea910d142a6fda3b6736b0f838c26fb602836556d42ef5d",
//       "0x039daa2808ea481212ffe576314b799e29c2f4e8cc2fd41c8c7585a160967082",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x017cd7c58551c6e910f7bf099a181a8fa90d2579a72f60eed858d084504edb29",
//       "0x10fb23e647a16ca0b7a637e108336e76ff7e11b875be1fccc1513add65262ea8",
//     ],
//     v_rest: [
//       "0x0f05f5caf268b3f16ec3b030e2f728d1edcf05f5ab3d555b88b0dea407a802b9",
//       "0x301c49b5df41d6b24808881a66dbc2abdb0e6cfb5da1c700c5a49afae32e65b7",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x29d7564bebd2f5c01bda45285d1f8914b0d23bbddab4fb461b6522a4a52fbc25",
//       "0x06215f74b089c23497f16fd97357a6b5b142934616e728ede91842cc70066825",
//     ],
//     v_rest: [
//       "0x04ef3e29e4452071f291e6ca9bd0d24e8ac09dda583f0c8b8d612ef176127a8f",
//       "0x10783d882e0efd4bd9dd10ff7b1b49a480dd8789bbed86b25ea77480e9d9e3a9",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x11748c1c2dda7d47351478e4550856febf13208a881cd45ef36010531ff98c52",
//       "0x26f5548bbf01689dc7b15482bc64ed9025f895d83f1e044802440eb639a14086",
//     ],
//     v_rest: [
//       "0x2abdc7fa38c6d0b2b82d0961e3ba19ee54a8cdd3909a127214a13d3bd0416c20",
//       "0x1107f6f7c9a4aec365dbfba8fd39e236fb15dc5a2bbc28ca3aa0c7d7575390ce",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x16e37ac41841b31187b70e2fdb793f7d6a76d4e424118d78edd247344ffffc27",
//       "0x13ff1dba1b980d01acafdb7c911020e7842cf6b4f38a9424516e02574cccd15e",
//     ],
//     v_rest: [
//       "0x0399f887bd393385be8f029b656c538b3585d6b961692216df74954a1b733d2f",
//       "0x0a2aca2f3ed2858c060472338853e3e9f2b714ac8e18ac87829e89f71097d8e9",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0e5cdb2ae335a1bc8c3b8e94888a0ce5b0aeb6ef0cd577319b852f5feffffffe",
//       "0x2a63a1d9344b65280ca9bccb251475131dba722c39811e4db49c96cb8666666a",
//     ],
//     v_rest: [
//       "0x0d4e6498c889123a5ea098172a037b4066352592ab23128330488859c0771609",
//       "0x0f51d08e12230c17f77633e048060ca234eda350603e99a276c4da0820f154a9",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x004250b7ef84d570d72936928796379e7e1e0928af8a0ee8c0b235c230000000",
//       "0x2667fe7f942c55b2c83b7c5d9cfc4993717044b05bcd63f97c38726a2b333334",
//     ],
//     v_rest: [
//       "0x00aadc8313ec8826c749036d0f132a681de0e001769f769e078653433dc40bc3",
//       "0x019c08a5ffcb302021b850174dfbbcd6cdddfa93e4ea5fd378dbaba9ebdf42e4",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x00002791220a45bfde7eebae2c8c2dbceb0943a46671eb090786637a24000000",
//       "0x135b23a7099e75f5382c65a31512cb80f3c259e571b89273efec6ba90999999a",
//     ],
//     v_rest: [
//       "0x18197c3c939a61b90fb61221287fa2d1eb097d20007bfe7a79a985c7a0b36619",
//       "0x177a17a30e038f011df8aae9de8e60385b075ef7a747d3b278a2e237d4f43275",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x000000179b8816ee9881d5072e746970cc6b958f16cb50fa60b33799ac000000",
//       "0x09ada92e2d50335b4157b9a9d3cb008e744f63f74b1715517c76edb572cccccd",
//     ],
//     v_rest: [
//       "0x24dbf2abb9268952d21c15bc7c850a19a142df074cadfd17080df7137dd265a7",
//       "0x209e252fc290f8856018bde541dc491722066ab82fad29917145a260dd37ea99",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x000000000e15dd23f00c4fc252f089b3baedd17f269dcbbad07ceed1a5000000",
//       "0x1d08fbde766929ba5b500a6f7618ca3de8228d76e04601a0c297991442666667",
//     ],
//     v_rest: [
//       "0x1ae1a7cefa24d1a38104df080e5ddedd42c4cf752ee90db9121c5222b01107ef",
//       "0x2bb8c81bba595be2c27ea5a422298e78cba2eec5c036592b822587291c738b95",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x000000000008676edfff3deb752fd68b591f10a5fecbe206f68a971e83000000",
//       "0x26b6a528b41dbbb238b489b8c45742327b82693b77536c7f62d811a7e2b33334",
//     ],
//     v_rest: [
//       "0x0c596b2c3008559df7c1732f9b62e53c08f9a9a81a7a1381d69136acd531142c",
//       "0x014b4fb2993e0900b3ddded3b0d21d03406f251bf2eab606d2bc30de83c4e42f",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0000000000000503a6355e4f26e4bb39feea5c4c1d045af23032ab16e4400000",
//       "0x135b52945a13d3b7dbffd67be0c595b2f5208b081b3e4f3cdce43d4d6e99999a",
//     ],
//     v_rest: [
//       "0x0f6bb89ce137c9f9db794f4df8f792fd2c428df25452ceff646bfbe04eff003a",
//       "0x0732f0a6ca5708c4a873a7d65e73bd0e722300ebbff2d8e0e49d576be38e125b",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0000000000000002fde3296da49b632bbf8eb3bef1298f5b90544f435ac00000",
//       "0x09ada94a2d09ecd198820da6ace71ca45957b22463429845cfc33c2a1b2ccccd",
//     ],
//     v_rest: [
//       "0x05c46dd180ca8e1f6a4500706bff4ab368cf75a3782e34562de8723080c11a08",
//       "0x1b88a4f4d1b9b78361be5471ebffe174c1f1afc60adae0e69ec8378952abe21e",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x000000000000000001c8f72b9fd259edd5fec26e1a95c35d5f5d11b1b0d00000",
//       "0x1d08fbde871dc67f6c78984f5378a28adc0b1da9dd744f7e8731283b1c266667",
//     ],
//     v_rest: [
//       "0x2ed03ce79a445472d16dff2c6c9ec06525af5a82aba6d7974794b3aa86c6d167",
//       "0x1124222effc83c5415c0a1cc06d7ecd267cd7571fe14915d5a41cd3322cb3a82",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0000000000000000000110a5d4202cc5ed960388f3630f771a487a3832300000",
//       "0x26b6a528b427b3549372279b0f4171841cc4ef216ed29acc722bbe344ceb3334",
//     ],
//     v_rest: [
//       "0x23fc71dd8f98f39f2247bc4aad79d67eccae785731b9cf9d0a3207be69153d65",
//       "0x056a9f6f85276f29b122fdab4deca5a12b84cd4b81f65e7c5b69f85490f5d1ec",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0000000000000000000000a2acc45ce46226d6641951633797c475447f640000",
//       "0x135b52945a13d9aa49b9b4bb44709ea3cf93345af9a6a079099c07fe2729999a",
//     ],
//     v_rest: [
//       "0x10ef90f0f9df49c3993e599067f6faeaf16e663a0cde19fd032836f1d948f6fe",
//       "0x0206c377e029a95c67bc1a9f27ad4537098f830a00d0fc399040e3047e8e47f6",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x000000000000000000000000610f4942c49cd7518cf504f3794bd536baac0000",
//       "0x09ada94a2d09ecd524dcdabda6c96387b9d9c64c9acc0ce0121443f59ea2cccd",
//     ],
//     v_rest: [
//       "0x09bd04de4e5b26edc69a6e7b3c3d02656ef36352b39da00991629b285696a296",
//       "0x02d2d2991b0e9ec6c3c5e41fa4cb0c60417b4c103429aadd1d7dd57066343a0b",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0000000000000000000000000039e9185606334ddc99a18465cf476226b50000",
//       "0x1d08fbde871dc67f6e96903a4d6f5304830dc4f2b6360c21b165fc9f38d26667",
//     ],
//     v_rest: [
//       "0x2ef39e64aaa3bc637d0a494b89b697fdaf53925890fd404aeecef1de7b12b45b",
//       "0x1571e4eafd0be12bf4e58e04f7f9e1bbd764ce0951ff39b331b1afbbd3d7c3e4",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0000000000000000000000000000228d5ec29c63fa0ca822a29b5305c6030000",
//       "0x26b6a528b427b35493736af8679a841c931be2fbcc9997b97f5eb4bb70dab334",
//     ],
//     v_rest: [
//       "0x1c20c3ab26ae12b1b586fa4a6f7abccedda563b22b0741baab41348bd2281ea3",
//       "0x2cb5e878ec684cd074b1003a2e2ea0a5cf8826d9ffdbf3b2ae3ccb21c30ce227",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x000000000000000000000000000000149d9395122a47abe7ced4fcea89584000",
//       "0x135b52945a13d9aa49b9b57c33cd5673366402f4021014e840b11e953ed6999a",
//     ],
//     v_rest: [
//       "0x1d1475887048709eb5ee4ec607860a2fbcd9e3ed29dde1bf596aa6a023a406f8",
//       "0x25169f46388d757ec304f3ca5da3497f320ca74c42e19a57dd4354f87bc57c40",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x000000000000000000000000000000000c4cdb9eef9e407e9605da822f8ac000",
//       "0x09ada94a2d09ecd524dcdabe19e6ab45c64095e100597ef4f25d14a6e0a12ccd",
//     ],
//     v_rest: [
//       "0x0a983a1d2e2af63f1a1dd6054a142a830d921d33c6566c8a6b894c643754fa15",
//       "0x2da025958107fbd536b163b49d6f3607fc55d3d61c41ba12f489a518b9d8974e",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x00000000000000000000000000000000000756c2df1fda0a197815e41e69d000",
//       "0x1d08fbde871dc67f6e96903a4db401d17e7cd720ffd42c72b7c0278212ae2667",
//     ],
//     v_rest: [
//       "0x13f6c13a7b7b0960f951fde960497374849207c7e10698002cf7cf108413b967",
//       "0x1deecb85209766fde6409249956d62da43e644384c7324badb47a0c17d7fcacf",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0000000000000000000000000000000000000460f5c1daf58bdd2e2371323000",
//       "0x26b6a528b427b35493736af8679aad17535cb4a21a95ca5542cac4e551a46b34",
//     ],
//     v_rest: [
//       "0x118e130b592b2508be3dc7a774356b424f24523622bf5e9e96e971406b09fed6",
//       "0x0b9cb01c17bb852374aaeccd338fc82a40e329ebdaf420a3ab53320b819d8d01",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x00000000000000000000000000000000000000029cd1ad7037a75ea21dd8a400",
//       "0x135b52945a13d9aa49b9b57c33cd568ba9ae5ce6b10f4315774b88758193a99a",
//     ],
//     v_rest: [
//       "0x2be0a2a6e9cc10c7fad6516e548a62de385ab6a02a27994ddb8925c3cfc98398",
//       "0x0df6a3864a4cb0564e97ae0985cc93057710584aa2eb8c191885b5bac8e3c180",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0000000000000000000000000000000000000000018f0cc3896bcc7f7a7fac00",
//       "0x09ada94a2d09ecd524dcdabe19e6ab45d4d72e74e34bcef3aa1c4c71b3ad02cd",
//     ],
//     v_rest: [
//       "0x1da8f76db6cd55307648b70c15f3b4a5efb16e837ebc044732b7a183aedbcb7a",
//       "0x0ebfb43926f7a4248e80a6fe0d7a5a07819a2b7de6dc09cb57451b6dece487c6",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x00000000000000000000000000000000000000000000ee17ad0a35fcd91cc500",
//       "0x1d08fbde871dc67f6e96903a4db401d17e858b5eaf6e2928b16c7649436af267",
//     ],
//     v_rest: [
//       "0x0f86099e1a507897272b314d1bbf49c6fef64a27dc60bf27dfd2efd57f13b12e",
//       "0x047a5f98256a3ab4af4c633d90cc62311ec156ca0408ff44174a643c80a8bd08",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x00000000000000000000000000000000000000000000008e0eb941affc868300",
//       "0x26b6a528b427b35493736af8679aad17535cb9d39494596554635b982e9412b4",
//     ],
//     v_rest: [
//       "0x0ef8b34e6212dbde61cae89f81a435cc12de778d931e4c9e31bff4862f6d83a2",
//       "0x2e240044d4480533d3df806e8a02ab7d31686ee6971741da40ea196d97f2bc51",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x00000000000000000000000000000000000000000000000054c2265380ab0c40",
//       "0x135b52945a13d9aa49b9b57c33cd568ba9ae5ce9ca4a2d06836da13edcee9e9a",
//     ],
//     v_rest: [
//       "0x162649b85f4a0b7a5acbb1d94b88338e8227a77072429c792deb2b3da3e21407",
//       "0x0edb8cec9280461358aff234fa814626acd34f4ed64605c5af8391ad9b1b6429",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0000000000000000000000000000000000000000000000000032922aea49fac0",
//       "0x09ada94a2d09ecd524dcdabe19e6ab45d4d72e74e525168373be038d8e26372d",
//     ],
//     v_rest: [
//       "0x2c2905f1de8af363d98fbc350421d64a13183f947c14cf64cd6b981b0e7deb39",
//       "0x0c281228c23673c5800fb4723e2052155754f4be3b0cadf9245f284f0f822ab1",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x00000000000000000000000000000000000000000000000000001e2c4f9db2d0",
//       "0x1d08fbde871dc67f6e96903a4db401d17e858b5eaf6f438a5bedd5f601735027",
//     ],
//     v_rest: [
//       "0x187b44d18483b81b0160156dca32062f5ada38ee06d34d842a9e670667c25e73",
//       "0x2056879a19a0038778005def063c8b2f8fe4cff9addad9c28045a72d50d711fb",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0000000000000000000000000000000000000000000000000000001200b2c230",
//       "0x26b6a528b427b35493736af8679aad17535cb9d394945a0dcfe7f79432cf53ec",
//     ],
//     v_rest: [
//       "0x23487958230bd60286efa0c458c56e79b1e0cab3f543dbc0005f4439843da928",
//       "0x07c407fffb71a9185c1a0106e93c896961a7c4f80f2f81dcdde6938656443880",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x000000000000000000000000000000000000000000000000000000000abdc5e4",
//       "0x135b52945a13d9aa49b9b57c33cd568ba9ae5ce9ca4a2d06e7f3fbd4b9a9202a",
//     ],
//     v_rest: [
//       "0x1a2508750d4813fc7cbdc83c052679d2bac3ef95df7a54c78338e730476496bf",
//       "0x0fcaf6642b1498525475e74befbaa506f5a9248d7bf442091790a75b6092dba1",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x00000000000000000000000000000000000000000000000000000000000668ac",
//       "0x09ada94a2d09ecd524dcdabe19e6ab45d4d72e74e525168373f9fdea632b9963",
//     ],
//     v_rest: [
//       "0x22933f915e5b956e43f16df2cdcc9e4567571164235d20ef82a268ceba41d41e",
//       "0x25f368f1a9599123da6a2453f2558fa1a4427b63e945877209f5cad6800c89ee",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x00000000000000000000000000000000000000000000000000000000000003d5",
//       "0x1d08fbde871dc67f6e96903a4db401d17e858b5eaf6f438a5bedf9bf29999513",
//     ],
//     v_rest: [
//       "0x2c5bf293f91828263e49953ca1613baaba2f94ed1a3f51da7e39cbc79c000001",
//       "0x1c66c18bf4ede32e6db2c4f3f3a055148a7d8ce64500a51d2e3d9b683257c57d",
//     ],
//   },
//   SparseMatrix {
//     w_hat: [
//       "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
//       "0x0000000000000000000000000000000000000000000000000000000000000003",
//       "0x0e847def438ee33fb74b481d26da00e8bf42c5af57b7a1c52df6fcdf94cccccb",
//     ],
//     v_rest: [
//       "0x244b3ad628e5381f4a3c3448e1210245de26ee365b4b146cf2e9782ef4000001",
//       "0x135b52945a13d9aa49b9b57c33cd568ba9ae5ce9ca4a2d06e7f3fbd4c6666667",
//     ],
//   },
// ];

// const T: usize = 3; // width
// const N_ROUNDS_F: usize = 8; // full_rounds
// const N_ROUNDS_P: usize = 57; // partial_rounds
// const C: [&str; T * (N_ROUNDS_F + N_ROUNDS_P)] = [
//   "0x0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e", "0x00f1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864", "0x08dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5", "0x2f27be690fdaee46c3ce28f7532b13c856c35342c84bda6e20966310fadc01d0", "0x2b2ae1acf68b7b8d2416bebf3d4f6234b763fe04b8043ee48b8327bebca16cf2", "0x0319d062072bef7ecca5eac06f97d4d55952c175ab6b03eae64b44c7dbf11cfa", "0x28813dcaebaeaa828a376df87af4a63bc8b7bf27ad49c6298ef7b387bf28526d", "0x2727673b2ccbc903f181bf38e1c1d40d2033865200c352bc150928adddf9cb78", "0x234ec45ca27727c2e74abd2b2a1494cd6efbd43e340587d6b8fb9e31e65cc632", "0x15b52534031ae18f7f862cb2cf7cf760ab10a8150a337b1ccd99ff6e8797d428", "0x0dc8fad6d9e4b35f5ed9a3d186b79ce38e0e8a8d1b58b132d701d4eecf68d1f6", "0x1bcd95ffc211fbca600f705fad3fb567ea4eb378f62e1fec97805518a47e4d9c", "0x10520b0ab721cadfe9eff81b016fc34dc76da36c2578937817cb978d069de559", "0x1f6d48149b8e7f7d9b257d8ed5fbbaf42932498075fed0ace88a9eb81f5627f6", "0x1d9655f652309014d29e00ef35a2089bfff8dc1c816f0dc9ca34bdb5460c8705", "0x04df5a56ff95bcafb051f7b1cd43a99ba731ff67e47032058fe3d4185697cc7d", "0x0672d995f8fff640151b3d290cedaf148690a10a8c8424a7f6ec282b6e4be828", "0x099952b414884454b21200d7ffafdd5f0c9a9dcc06f2708e9fc1d8209b5c75b9", "0x052cba2255dfd00c7c483143ba8d469448e43586a9b4cd9183fd0e843a6b9fa6", "0x0b8badee690adb8eb0bd74712b7999af82de55707251ad7716077cb93c464ddc", "0x119b1590f13307af5a1ee651020c07c749c15d60683a8050b963d0a8e4b2bdd1", "0x03150b7cd6d5d17b2529d36be0f67b832c4acfc884ef4ee5ce15be0bfb4a8d09", "0x2cc6182c5e14546e3cf1951f173912355374efb83d80898abe69cb317c9ea565", "0x005032551e6378c450cfe129a404b3764218cadedac14e2b92d2cd73111bf0f9", "0x233237e3289baa34bb147e972ebcb9516469c399fcc069fb88f9da2cc28276b5", "0x05c8f4f4ebd4a6e3c980d31674bfbe6323037f21b34ae5a4e80c2d4c24d60280", "0x0a7b1db13042d396ba05d818a319f25252bcf35ef3aeed91ee1f09b2590fc65b", "0x2a73b71f9b210cf5b14296572c9d32dbf156e2b086ff47dc5df542365a404ec0", "0x1ac9b0417abcc9a1935107e9ffc91dc3ec18f2c4dbe7f22976a760bb5c50c460", "0x12c0339ae08374823fabb076707ef479269f3e4d6cb104349015ee046dc93fc0", "0x0b7475b102a165ad7f5b18db4e1e704f52900aa3253baac68246682e56e9a28e", "0x037c2849e191ca3edb1c5e49f6e8b8917c843e379366f2ea32ab3aa88d7f8448", "0x05a6811f8556f014e92674661e217e9bd5206c5c93a07dc145fdb176a716346f", "0x29a795e7d98028946e947b75d54e9f044076e87a7b2883b47b675ef5f38bd66e", "0x20439a0c84b322eb45a3857afc18f5826e8c7382c8a1585c507be199981fd22f", "0x2e0ba8d94d9ecf4a94ec2050c7371ff1bb50f27799a84b6d4a2a6f2a0982c887", "0x143fd115ce08fb27ca38eb7cce822b4517822cd2109048d2e6d0ddcca17d71c8", "0x0c64cbecb1c734b857968dbbdcf813cdf8611659323dbcbfc84323623be9caf1", "0x028a305847c683f646fca925c163ff5ae74f348d62c2b670f1426cef9403da53", "0x2e4ef510ff0b6fda5fa940ab4c4380f26a6bcb64d89427b824d6755b5db9e30c", "0x0081c95bc43384e663d79270c956ce3b8925b4f6d033b078b96384f50579400e", "0x2ed5f0c91cbd9749187e2fade687e05ee2491b349c039a0bba8a9f4023a0bb38", "0x30509991f88da3504bbf374ed5aae2f03448a22c76234c8c990f01f33a735206", "0x1c3f20fd55409a53221b7c4d49a356b9f0a1119fb2067b41a7529094424ec6ad", "0x10b4e7f3ab5df003049514459b6e18eec46bb2213e8e131e170887b47ddcb96c", "0x2a1982979c3ff7f43ddd543d891c2abddd80f804c077d775039aa3502e43adef", "0x1c74ee64f15e1db6feddbead56d6d55dba431ebc396c9af95cad0f1315bd5c91", "0x07533ec850ba7f98eab9303cace01b4b9e4f2e8b82708cfa9c2fe45a0ae146a0", "0x21576b438e500449a151e4eeaf17b154285c68f42d42c1808a11abf3764c0750", "0x2f17c0559b8fe79608ad5ca193d62f10bce8384c815f0906743d6930836d4a9e", "0x2d477e3862d07708a79e8aae946170bc9775a4201318474ae665b0b1b7e2730e", "0x162f5243967064c390e095577984f291afba2266c38f5abcd89be0f5b2747eab", "0x2b4cb233ede9ba48264ecd2c8ae50d1ad7a8596a87f29f8a7777a70092393311", "0x2c8fbcb2dd8573dc1dbaf8f4622854776db2eece6d85c4cf4254e7c35e03b07a", "0x1d6f347725e4816af2ff453f0cd56b199e1b61e9f601e9ade5e88db870949da9", "0x204b0c397f4ebe71ebc2d8b3df5b913df9e6ac02b68d31324cd49af5c4565529", "0x0c4cb9dc3c4fd8174f1149b3c63c3c2f9ecb827cd7dc25534ff8fb75bc79c502", "0x174ad61a1448c899a25416474f4930301e5c49475279e0639a616ddc45bc7b54", "0x1a96177bcf4d8d89f759df4ec2f3cde2eaaa28c177cc0fa13a9816d49a38d2ef", "0x066d04b24331d71cd0ef8054bc60c4ff05202c126a233c1a8242ace360b8a30a", "0x2a4c4fc6ec0b0cf52195782871c6dd3b381cc65f72e02ad527037a62aa1bd804", "0x13ab2d136ccf37d447e9f2e14a7cedc95e727f8446f6d9d7e55afc01219fd649", "0x1121552fca26061619d24d843dc82769c1b04fcec26f55194c2e3e869acc6a9a", "0x00ef653322b13d6c889bc81715c37d77a6cd267d595c4a8909a5546c7c97cff1", "0x0e25483e45a665208b261d8ba74051e6400c776d652595d9845aca35d8a397d3", "0x29f536dcb9dd7682245264659e15d88e395ac3d4dde92d8c46448db979eeba89", "0x2a56ef9f2c53febadfda33575dbdbd885a124e2780bbea170e456baace0fa5be", "0x1c8361c78eb5cf5decfb7a2d17b5c409f2ae2999a46762e8ee416240a8cb9af1", "0x151aff5f38b20a0fc0473089aaf0206b83e8e68a764507bfd3d0ab4be74319c5", "0x04c6187e41ed881dc1b239c88f7f9d43a9f52fc8c8b6cdd1e76e47615b51f100", "0x13b37bd80f4d27fb10d84331f6fb6d534b81c61ed15776449e801b7ddc9c2967", "0x01a5c536273c2d9df578bfbd32c17b7a2ce3664c2a52032c9321ceb1c4e8a8e4", "0x2ab3561834ca73835ad05f5d7acb950b4a9a2c666b9726da832239065b7c3b02", "0x1d4d8ec291e720db200fe6d686c0d613acaf6af4e95d3bf69f7ed516a597b646", "0x041294d2cc484d228f5784fe7919fd2bb925351240a04b711514c9c80b65af1d", "0x154ac98e01708c611c4fa715991f004898f57939d126e392042971dd90e81fc6", "0x0b339d8acca7d4f83eedd84093aef51050b3684c88f8b0b04524563bc6ea4da4", "0x0955e49e6610c94254a4f84cfbab344598f0e71eaff4a7dd81ed95b50839c82e", "0x06746a6156eba54426b9e22206f15abca9a6f41e6f535c6f3525401ea0654626", "0x0f18f5a0ecd1423c496f3820c549c27838e5790e2bd0a196ac917c7ff32077fb", "0x04f6eeca1751f7308ac59eff5beb261e4bb563583ede7bc92a738223d6f76e13", "0x2b56973364c4c4f5c1a3ec4da3cdce038811eb116fb3e45bc1768d26fc0b3758", "0x123769dd49d5b054dcd76b89804b1bcb8e1392b385716a5d83feb65d437f29ef", "0x2147b424fc48c80a88ee52b91169aacea989f6446471150994257b2fb01c63e9", "0x0fdc1f58548b85701a6c5505ea332a29647e6f34ad4243c2ea54ad897cebe54d", "0x12373a8251fea004df68abcf0f7786d4bceff28c5dbbe0c3944f685cc0a0b1f2", "0x21e4f4ea5f35f85bad7ea52ff742c9e8a642756b6af44203dd8a1f35c1a90035", "0x16243916d69d2ca3dfb4722224d4c462b57366492f45e90d8a81934f1bc3b147", "0x1efbe46dd7a578b4f66f9adbc88b4378abc21566e1a0453ca13a4159cac04ac2", "0x07ea5e8537cf5dd08886020e23a7f387d468d5525be66f853b672cc96a88969a", "0x05a8c4f9968b8aa3b7b478a30f9a5b63650f19a75e7ce11ca9fe16c0b76c00bc", "0x20f057712cc21654fbfe59bd345e8dac3f7818c701b9c7882d9d57b72a32e83f", "0x04a12ededa9dfd689672f8c67fee31636dcd8e88d01d49019bd90b33eb33db69", "0x27e88d8c15f37dcee44f1e5425a51decbd136ce5091a6767e49ec9544ccd101a", "0x2feed17b84285ed9b8a5c8c5e95a41f66e096619a7703223176c41ee433de4d1", "0x1ed7cc76edf45c7c404241420f729cf394e5942911312a0d6972b8bd53aff2b8", "0x15742e99b9bfa323157ff8c586f5660eac6783476144cdcadf2874be45466b1a", "0x1aac285387f65e82c895fc6887ddf40577107454c6ec0317284f033f27d0c785", "0x25851c3c845d4790f9ddadbdb6057357832e2e7a49775f71ec75a96554d67c77", "0x15a5821565cc2ec2ce78457db197edf353b7ebba2c5523370ddccc3d9f146a67", "0x2411d57a4813b9980efa7e31a1db5966dcf64f36044277502f15485f28c71727", "0x002e6f8d6520cd4713e335b8c0b6d2e647e9a98e12f4cd2558828b5ef6cb4c9b", "0x2ff7bc8f4380cde997da00b616b0fcd1af8f0e91e2fe1ed7398834609e0315d2", "0x00b9831b948525595ee02724471bcd182e9521f6b7bb68f1e93be4febb0d3cbe", "0x0a2f53768b8ebf6a86913b0e57c04e011ca408648a4743a87d77adbf0c9c3512", "0x00248156142fd0373a479f91ff239e960f599ff7e94be69b7f2a290305e1198d", "0x171d5620b87bfb1328cf8c02ab3f0c9a397196aa6a542c2350eb512a2b2bcda9", "0x170a4f55536f7dc970087c7c10d6fad760c952172dd54dd99d1045e4ec34a808", "0x29aba33f799fe66c2ef3134aea04336ecc37e38c1cd211ba482eca17e2dbfae1", "0x1e9bc179a4fdd758fdd1bb1945088d47e70d114a03f6a0e8b5ba650369e64973", "0x1dd269799b660fad58f7f4892dfb0b5afeaad869a9c4b44f9c9e1c43bdaf8f09", "0x22cdbc8b70117ad1401181d02e15459e7ccd426fe869c7c95d1dd2cb0f24af38", "0x0ef042e454771c533a9f57a55c503fcefd3150f52ed94a7cd5ba93b9c7dacefd", "0x11609e06ad6c8fe2f287f3036037e8851318e8b08a0359a03b304ffca62e8284", "0x1166d9e554616dba9e753eea427c17b7fecd58c076dfe42708b08f5b783aa9af", "0x2de52989431a859593413026354413db177fbf4cd2ac0b56f855a888357ee466", "0x3006eb4ffc7a85819a6da492f3a8ac1df51aee5b17b8e89d74bf01cf5f71e9ad", "0x2af41fbb61ba8a80fdcf6fff9e3f6f422993fe8f0a4639f962344c8225145086", "0x119e684de476155fe5a6b41a8ebc85db8718ab27889e85e781b214bace4827c3", "0x1835b786e2e8925e188bea59ae363537b51248c23828f047cff784b97b3fd800", "0x28201a34c594dfa34d794996c6433a20d152bac2a7905c926c40e285ab32eeb6", "0x083efd7a27d1751094e80fefaf78b000864c82eb571187724a761f88c22cc4e7", "0x0b6f88a3577199526158e61ceea27be811c16df7774dd8519e079564f61fd13b", "0x0ec868e6d15e51d9644f66e1d6471a94589511ca00d29e1014390e6ee4254f5b", "0x2af33e3f866771271ac0c9b3ed2e1142ecd3e74b939cd40d00d937ab84c98591", "0x0b520211f904b5e7d09b5d961c6ace7734568c547dd6858b364ce5e47951f178", "0x0b2d722d0919a1aad8db58f10062a92ea0c56ac4270e822cca228620188a1d40", "0x1f790d4d7f8cf094d980ceb37c2453e957b54a9991ca38bbe0061d1ed6e562d4", "0x0171eb95dfbf7d1eaea97cd385f780150885c16235a2a6a8da92ceb01e504233", "0x0c2d0e3b5fd57549329bf6885da66b9b790b40defd2c8650762305381b168873", "0x1162fb28689c27154e5a8228b4e72b377cbcafa589e283c35d3803054407a18d", "0x2f1459b65dee441b64ad386a91e8310f282c5a92a89e19921623ef8249711bc0", "0x1e6ff3216b688c3d996d74367d5cd4c1bc489d46754eb712c243f70d1b53cfbb", "0x01ca8be73832b8d0681487d27d157802d741a6f36cdc2a0576881f9326478875", "0x1f7735706ffe9fc586f976d5bdf223dc680286080b10cea00b9b5de315f9650e", "0x2522b60f4ea3307640a0c2dce041fba921ac10a3d5f096ef4745ca838285f019", "0x23f0bee001b1029d5255075ddc957f833418cad4f52b6c3f8ce16c235572575b", "0x2bc1ae8b8ddbb81fcaac2d44555ed5685d142633e9df905f66d9401093082d59", "0x0f9406b8296564a37304507b8dba3ed162371273a07b1fc98011fcd6ad72205f", "0x2360a8eb0cc7defa67b72998de90714e17e75b174a52ee4acb126c8cd995f0a8", "0x15871a5cddead976804c803cbaef255eb4815a5e96df8b006dcbbc2767f88948", "0x193a56766998ee9e0a8652dd2f3b1da0362f4f54f72379544f957ccdeefb420f", "0x2a394a43934f86982f9be56ff4fab1703b2e63c8ad334834e4309805e777ae0f", "0x1859954cfeb8695f3e8b635dcb345192892cd11223443ba7b4166e8876c0d142", "0x04e1181763050e58013444dbcb99f1902b11bc25d90bbdca408d3819f4fed32b", "0x0fdb253dee83869d40c335ea64de8c5bb10eb82db08b5e8b1f5e5552bfd05f23", "0x058cbe8a9a5027bdaa4efb623adead6275f08686f1c08984a9d7c5bae9b4f1c0", "0x1382edce9971e186497eadb1aeb1f52b23b4b83bef023ab0d15228b4cceca59a", "0x03464990f045c6ee0819ca51fd11b0be7f61b8eb99f14b77e1e6634601d9e8b5", "0x23f7bfc8720dc296fff33b41f98ff83c6fcab4605db2eb5aaa5bc137aeb70a58", "0x0a59a158e3eec2117e6e94e7f0e9decf18c3ffd5e1531a9219636158bbaf62f2", "0x06ec54c80381c052b58bf23b312ffd3ce2c4eba065420af8f4c23ed0075fd07b", "0x118872dc832e0eb5476b56648e867ec8b09340f7a7bcb1b4962f0ff9ed1f9d01", "0x13d69fa127d834165ad5c7cba7ad59ed52e0b0f0e42d7fea95e1906b520921b1", "0x169a177f63ea681270b1c6877a73d21bde143942fb71dc55fd8a49f19f10c77b", "0x04ef51591c6ead97ef42f287adce40d93abeb032b922f66ffb7e9a5a7450544d", "0x256e175a1dc079390ecd7ca703fb2e3b19ec61805d4f03ced5f45ee6dd0f69ec", "0x30102d28636abd5fe5f2af412ff6004f75cc360d3205dd2da002813d3e2ceeb2", "0x10998e42dfcd3bbf1c0714bc73eb1bf40443a3fa99bef4a31fd31be182fcc792", "0x193edd8e9fcf3d7625fa7d24b598a1d89f3362eaf4d582efecad76f879e36860", "0x18168afd34f2d915d0368ce80b7b3347d1c7a561ce611425f2664d7aa51f0b5d", "0x29383c01ebd3b6ab0c017656ebe658b6a328ec77bc33626e29e2e95b33ea6111", "0x10646d2f2603de39a1f4ae5e7771a64a702db6e86fb76ab600bf573f9010c711", "0x0beb5e07d1b27145f575f1395a55bf132f90c25b40da7b3864d0242dcb1117fb", "0x16d685252078c133dc0d3ecad62b5c8830f95bb2e54b59abdffbf018d96fa336", "0x0a6abd1d833938f33c74154e0404b4b40a555bbbec21ddfafd672dd62047f01a", "0x1a679f5d36eb7b5c8ea12a4c2dedc8feb12dffeec450317270a6f19b34cf1860", "0x0980fb233bd456c23974d50e0ebfde4726a423eada4e8f6ffbc7592e3f1b93d6", "0x161b42232e61b84cbf1810af93a38fc0cece3d5628c9282003ebacb5c312c72b", "0x0ada10a90c7f0520950f7d47a60d5e6a493f09787f1564e5d09203db47de1a0b", "0x1a730d372310ba82320345a29ac4238ed3f07a8a2b4e121bb50ddb9af407f451", "0x2c8120f268ef054f817064c369dda7ea908377feaba5c4dffbda10ef58e8c556", "0x1c7c8824f758753fa57c00789c684217b930e95313bcb73e6e7b8649a4968f70", "0x2cd9ed31f5f8691c8e39e4077a74faa0f400ad8b491eb3f7b47b27fa3fd1cf77", "0x23ff4f9d46813457cf60d92f57618399a5e022ac321ca550854ae23918a22eea", "0x09945a5d147a4f66ceece6405dddd9d0af5a2c5103529407dff1ea58f180426d", "0x188d9c528025d4c2b67660c6b771b90f7c7da6eaa29d3f268a6dd223ec6fc630", "0x3050e37996596b7f81f68311431d8734dba7d926d3633595e0c0d8ddf4f0f47f", "0x15af1169396830a91600ca8102c35c426ceae5461e3f95d89d829518d30afd78", "0x1da6d09885432ea9a06d9f37f873d985dae933e351466b2904284da3320d8acc", "0x2796ea90d269af29f5f8acf33921124e4e4fad3dbe658945e546ee411ddaa9cb", "0x202d7dd1da0f6b4b0325c8b3307742f01e15612ec8e9304a7cb0319e01d32d60", "0x096d6790d05bb759156a952ba263d672a2d7f9c788f4c831a29dace4c0f8be5f", "0x054efa1f65b0fce283808965275d877b438da23ce5b13e1963798cb1447d25a4", "0x1b162f83d917e93edb3308c29802deb9d8aa690113b2e14864ccf6e18e4165f1", "0x21e5241e12564dd6fd9f1cdd2a0de39eedfefc1466cc568ec5ceb745a0506edc", "0x1cfb5662e8cf5ac9226a80ee17b36abecb73ab5f87e161927b4349e10e4bdf08", "0x0f21177e302a771bbae6d8d1ecb373b62c99af346220ac0129c53f666eb24100", "0x1671522374606992affb0dd7f71b12bec4236aede6290546bcef7e1f515c2320", "0x0fa3ec5b9488259c2eb4cf24501bfad9be2ec9e42c5cc8ccd419d2a692cad870", "0x193c0e04e0bd298357cb266c1506080ed36edce85c648cc085e8c57b1ab54bba", "0x102adf8ef74735a27e9128306dcbc3c99f6f7291cd406578ce14ea2adaba68f8", "0x0fe0af7858e49859e2a54d6f1ad945b1316aa24bfbdd23ae40a6d0cb70c3eab1", "0x216f6717bbc7dedb08536a2220843f4e2da5f1daa9ebdefde8a5ea7344798d22", "0x1da55cc900f0d21f4a3e694391918a1b3c23b2ac773c6b3ef88e2e4228325161"
// ];
// const M: [[&str; T]; T] = [
//   [
//     "0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
//     "0x16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0",
//     "0x2b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d",
//   ],
//   [
//     "0x2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771",
//     "0x2e2419f9ec02ec394c9871c832963dc1b89d743c8c7b964029b2311687b1fe23",
//     "0x101071f0032379b697315876690f053d148d4e109f5fb065c8aacc55a0f89bfa",
//   ],
//   [
//     "0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7",
//     "0x176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911",
//     "0x19a3fc0a56702bf417ba7fee3802593fa644470307043f7773279cd71d25d5e0",
//   ],
// ];
