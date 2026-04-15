// URDF parser and forward kinematics solver.
//
// Parses a URDF (Unified Robot Description Format) XML file into a kinematic
// tree, then computes forward kinematics to determine link positions from
// joint angles. This enables zero-trust self-collision checking: Invariant
// computes link positions independently from joint states instead of relying
// on the cognitive layer's reported end-effector positions.
//
// Scope: revolute and fixed joints only (covers >95% of robot URDFs).
// Prismatic joints are parsed but treated as fixed at zero displacement.

use std::collections::HashMap;

use quick_xml::events::Event;
use quick_xml::Reader;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur while parsing a URDF file or computing forward kinematics.
#[derive(Debug, Error)]
pub enum UrdfError {
    /// The XML input could not be parsed.
    #[error("XML parse error: {0}")]
    XmlParse(String),

    /// A required XML attribute was absent on the given element.
    #[error("missing attribute '{attr}' on element '{element}'")]
    MissingAttribute {
        /// The element tag where the attribute was expected.
        element: String,
        /// The name of the missing attribute.
        attr: String,
    },

    /// A string value could not be parsed as an `f64` in the given context.
    #[error("invalid float in '{context}': {value}")]
    InvalidFloat {
        /// The XML context (e.g. `"origin xyz"`) where parsing failed.
        context: String,
        /// The raw string that could not be converted to a float.
        value: String,
    },

    /// A joint referenced a parent link that was not declared.
    #[error("unknown parent link '{parent}' in joint '{joint}'")]
    UnknownParent {
        /// The name of the joint that has the unknown parent.
        joint: String,
        /// The name of the parent link that was not found.
        parent: String,
    },

    /// No root link could be identified (every link is a child of some joint).
    #[error("no root link found (no link is never a child)")]
    NoRootLink,

    /// The URDF contains more links than the hard limit allows.
    #[error("URDF too large: {count} links exceeds limit {max}")]
    TooManyLinks {
        /// Actual number of links found in the URDF.
        count: usize,
        /// Maximum number of links permitted.
        max: usize,
    },
}

// ---------------------------------------------------------------------------
// URDF data model
// ---------------------------------------------------------------------------

/// A 3D transform: translation `[x,y,z]` + rotation `[roll,pitch,yaw]` (RPY).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Transform {
    /// Translation vector `[x, y, z]` in metres.
    pub xyz: [f64; 3],
    /// Rotation as roll-pitch-yaw `[roll, pitch, yaw]` in radians.
    pub rpy: [f64; 3],
}

impl Default for Transform {
    fn default() -> Self {
        Self {
            xyz: [0.0; 3],
            rpy: [0.0; 3],
        }
    }
}

impl Transform {
    /// Convert this transform to a 4x4 homogeneous transformation matrix.
    /// Rotation order: Z(yaw) * Y(pitch) * X(roll), matching URDF convention.
    pub fn to_matrix(&self) -> [[f64; 4]; 4] {
        let [roll, pitch, yaw] = self.rpy;
        let (sr, cr) = roll.sin_cos();
        let (sp, cp) = pitch.sin_cos();
        let (sy, cy) = yaw.sin_cos();

        // R = Rz(yaw) * Ry(pitch) * Rx(roll)
        [
            [
                cy * cp,
                cy * sp * sr - sy * cr,
                cy * sp * cr + sy * sr,
                self.xyz[0],
            ],
            [
                sy * cp,
                sy * sp * sr + cy * cr,
                sy * sp * cr - cy * sr,
                self.xyz[1],
            ],
            [-sp, cp * sr, cp * cr, self.xyz[2]],
            [0.0, 0.0, 0.0, 1.0],
        ]
    }
}

/// Joint type from the URDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrdfJointType {
    /// Revolute joint: rotates around an axis within defined limits.
    Revolute,
    /// Continuous joint: rotates around an axis without limits.
    Continuous,
    /// Prismatic joint: translates along an axis (treated as fixed at zero).
    Prismatic,
    /// Fixed joint: no relative motion between parent and child link.
    Fixed,
}

/// A joint parsed from the URDF.
#[derive(Debug, Clone)]
pub struct UrdfJoint {
    /// Unique joint name as declared in the URDF.
    pub name: String,
    /// Kinematic type of this joint.
    pub joint_type: UrdfJointType,
    /// Name of the parent link in the kinematic tree.
    pub parent_link: String,
    /// Name of the child link in the kinematic tree.
    pub child_link: String,
    /// Transform from parent link frame to joint frame.
    pub origin: Transform,
    /// Rotation axis (unit vector) for revolute/continuous joints.
    pub axis: [f64; 3],
}

/// A link parsed from the URDF (just name — geometry is not needed for FK).
#[derive(Debug, Clone)]
pub struct UrdfLink {
    /// Unique link name as declared in the URDF.
    pub name: String,
}

/// Parsed URDF robot model.
#[derive(Debug, Clone)]
pub struct UrdfModel {
    /// Robot name from the `<robot name="...">` attribute.
    pub name: String,
    /// All links declared in the URDF.
    pub links: Vec<UrdfLink>,
    /// All joints declared in the URDF.
    pub joints: Vec<UrdfJoint>,
}

/// Maximum number of links allowed (DoS guard).
const MAX_LINKS: usize = 512;

// ---------------------------------------------------------------------------
// URDF parser
// ---------------------------------------------------------------------------

/// Parse a URDF XML string into a `UrdfModel`.
pub fn parse_urdf(xml: &str) -> Result<UrdfModel, UrdfError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut robot_name = String::new();
    let mut links: Vec<UrdfLink> = Vec::new();
    let mut joints: Vec<UrdfJoint> = Vec::new();

    // Current joint being parsed (joint elements have child elements).
    let mut current_joint: Option<JointBuilder> = None;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local = e.local_name();
                let tag = std::str::from_utf8(local.as_ref()).unwrap_or("");

                match tag {
                    "robot" => {
                        robot_name = attr_str(e, "name").unwrap_or_default();
                    }
                    "link" => {
                        if let Some(name) = attr_str(e, "name") {
                            links.push(UrdfLink { name });
                        }
                    }
                    "joint" => {
                        let name = attr_str(e, "name").unwrap_or_default();
                        let jtype = match attr_str(e, "type").as_deref() {
                            Some("revolute") => UrdfJointType::Revolute,
                            Some("continuous") => UrdfJointType::Continuous,
                            Some("prismatic") => UrdfJointType::Prismatic,
                            _ => UrdfJointType::Fixed,
                        };
                        current_joint = Some(JointBuilder {
                            name,
                            joint_type: jtype,
                            parent: String::new(),
                            child: String::new(),
                            origin: Transform::default(),
                            axis: [0.0, 0.0, 1.0], // default Z-axis
                        });
                    }
                    "parent" if current_joint.is_some() => {
                        if let (Some(ref mut builder), Some(link)) =
                            (&mut current_joint, attr_str(e, "link"))
                        {
                            builder.parent = link;
                        }
                    }
                    "child" if current_joint.is_some() => {
                        if let (Some(ref mut builder), Some(link)) =
                            (&mut current_joint, attr_str(e, "link"))
                        {
                            builder.child = link;
                        }
                    }
                    "origin" if current_joint.is_some() => {
                        if let Some(ref mut builder) = current_joint {
                            if let Some(xyz_str) = attr_str(e, "xyz") {
                                builder.origin.xyz = parse_vec3(&xyz_str, "origin xyz")?;
                            }
                            if let Some(rpy_str) = attr_str(e, "rpy") {
                                builder.origin.rpy = parse_vec3(&rpy_str, "origin rpy")?;
                            }
                        }
                    }
                    "axis" if current_joint.is_some() => {
                        if let (Some(ref mut builder), Some(xyz_str)) =
                            (&mut current_joint, attr_str(e, "xyz"))
                        {
                            builder.axis = parse_vec3(&xyz_str, "axis xyz")?;
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let local = e.local_name();
                let tag = std::str::from_utf8(local.as_ref()).unwrap_or("");
                if tag == "joint" {
                    if let Some(builder) = current_joint.take() {
                        joints.push(UrdfJoint {
                            name: builder.name,
                            joint_type: builder.joint_type,
                            parent_link: builder.parent,
                            child_link: builder.child,
                            origin: builder.origin,
                            axis: builder.axis,
                        });
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(UrdfError::XmlParse(e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    if links.len() > MAX_LINKS {
        return Err(UrdfError::TooManyLinks {
            count: links.len(),
            max: MAX_LINKS,
        });
    }

    Ok(UrdfModel {
        name: robot_name,
        links,
        joints,
    })
}

struct JointBuilder {
    name: String,
    joint_type: UrdfJointType,
    parent: String,
    child: String,
    origin: Transform,
    axis: [f64; 3],
}

fn attr_str(e: &quick_xml::events::BytesStart, name: &str) -> Option<String> {
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == name.as_bytes())
        .and_then(|a| String::from_utf8(a.value.to_vec()).ok())
}

fn parse_vec3(s: &str, context: &str) -> Result<[f64; 3], UrdfError> {
    let parts: Vec<f64> = s
        .split_whitespace()
        .map(|p| {
            p.parse::<f64>().map_err(|_| UrdfError::InvalidFloat {
                context: context.to_string(),
                value: p.to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    if parts.len() != 3 {
        return Err(UrdfError::InvalidFloat {
            context: context.to_string(),
            value: s.to_string(),
        });
    }
    Ok([parts[0], parts[1], parts[2]])
}

// ---------------------------------------------------------------------------
// Forward kinematics
// ---------------------------------------------------------------------------

/// Multiply two 4x4 homogeneous matrices.
fn mat4_mul(a: &[[f64; 4]; 4], b: &[[f64; 4]; 4]) -> [[f64; 4]; 4] {
    let mut result = [[0.0f64; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            for k in 0..4 {
                result[i][j] += a[i][k] * b[k][j];
            }
        }
    }
    result
}

/// Build the rotation matrix for a revolute joint: rotate `angle` radians
/// around `axis`.
fn revolute_rotation(axis: &[f64; 3], angle: f64) -> [[f64; 4]; 4] {
    let [x, y, z] = *axis;
    let norm = (x * x + y * y + z * z).sqrt();
    let (ux, uy, uz) = if norm > 1e-12 {
        (x / norm, y / norm, z / norm)
    } else {
        (0.0, 0.0, 1.0)
    };

    let (s, c) = angle.sin_cos();
    let t = 1.0 - c;

    [
        [
            t * ux * ux + c,
            t * ux * uy - s * uz,
            t * ux * uz + s * uy,
            0.0,
        ],
        [
            t * uy * ux + s * uz,
            t * uy * uy + c,
            t * uy * uz - s * ux,
            0.0,
        ],
        [
            t * uz * ux - s * uy,
            t * uz * uy + s * ux,
            t * uz * uz + c,
            0.0,
        ],
        [0.0, 0.0, 0.0, 1.0],
    ]
}

/// Extract the translation (position) from a 4x4 homogeneous matrix.
fn mat4_position(m: &[[f64; 4]; 4]) -> [f64; 3] {
    [m[0][3], m[1][3], m[2][3]]
}

/// Compute forward kinematics for all links in the URDF model.
///
/// `joint_angles` maps joint name → angle (radians). Joints not in the map
/// are treated as zero angle (default position).
///
/// Returns a map of link name → world-frame position [x, y, z].
pub fn forward_kinematics(
    model: &UrdfModel,
    joint_angles: &HashMap<String, f64>,
) -> Result<HashMap<String, [f64; 3]>, UrdfError> {
    // Build parent-child adjacency from joints.
    // child_link → (joint, parent_link)
    let mut child_to_joint: HashMap<&str, &UrdfJoint> = HashMap::new();
    for joint in &model.joints {
        child_to_joint.insert(&joint.child_link, joint);
    }

    // Find root link (a link that is never a child).
    let child_links: std::collections::HashSet<&str> =
        model.joints.iter().map(|j| j.child_link.as_str()).collect();
    let root = model
        .links
        .iter()
        .find(|l| !child_links.contains(l.name.as_str()))
        .ok_or(UrdfError::NoRootLink)?;

    // Compute transform for each link via BFS from root.
    let mut link_transforms: HashMap<&str, [[f64; 4]; 4]> = HashMap::new();
    let identity: [[f64; 4]; 4] = [
        [1.0, 0.0, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
        [0.0, 0.0, 0.0, 1.0],
    ];
    link_transforms.insert(&root.name, identity);

    // Parent → children adjacency.
    let mut parent_to_children: HashMap<&str, Vec<&UrdfJoint>> = HashMap::new();
    for joint in &model.joints {
        parent_to_children
            .entry(&joint.parent_link)
            .or_default()
            .push(joint);
    }

    // BFS.
    let mut queue: Vec<&str> = vec![&root.name];
    while let Some(parent_name) = queue.pop() {
        let parent_tf = link_transforms[parent_name];

        if let Some(children) = parent_to_children.get(parent_name) {
            for joint in children {
                // T_child = T_parent * T_origin * R_joint(angle)
                let origin_tf = joint.origin.to_matrix();
                let joint_tf = match joint.joint_type {
                    UrdfJointType::Revolute | UrdfJointType::Continuous => {
                        let angle = joint_angles.get(&joint.name).copied().unwrap_or(0.0);
                        revolute_rotation(&joint.axis, angle)
                    }
                    _ => identity,
                };

                let combined = mat4_mul(&mat4_mul(&parent_tf, &origin_tf), &joint_tf);
                link_transforms.insert(&joint.child_link, combined);
                queue.push(&joint.child_link);
            }
        }
    }

    // Extract positions.
    let mut positions: HashMap<String, [f64; 3]> = HashMap::new();
    for (name, tf) in &link_transforms {
        positions.insert(name.to_string(), mat4_position(tf));
    }

    Ok(positions)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_URDF: &str = r#"
    <robot name="test_robot">
      <link name="base_link"/>
      <link name="link1"/>
      <link name="link2"/>
      <joint name="joint1" type="revolute">
        <parent link="base_link"/>
        <child link="link1"/>
        <origin xyz="0 0 1" rpy="0 0 0"/>
        <axis xyz="0 0 1"/>
      </joint>
      <joint name="joint2" type="revolute">
        <parent link="link1"/>
        <child link="link2"/>
        <origin xyz="1 0 0" rpy="0 0 0"/>
        <axis xyz="0 0 1"/>
      </joint>
    </robot>
    "#;

    const FIXED_JOINT_URDF: &str = r#"
    <robot name="fixed_robot">
      <link name="base"/>
      <link name="sensor"/>
      <joint name="sensor_mount" type="fixed">
        <parent link="base"/>
        <child link="sensor"/>
        <origin xyz="0 0 0.5" rpy="0 0 0"/>
      </joint>
    </robot>
    "#;

    // -- Parser tests --

    #[test]
    fn parse_simple_urdf() {
        let model = parse_urdf(SIMPLE_URDF).unwrap();
        assert_eq!(model.name, "test_robot");
        assert_eq!(model.links.len(), 3);
        assert_eq!(model.joints.len(), 2);
        assert_eq!(model.joints[0].name, "joint1");
        assert_eq!(model.joints[0].parent_link, "base_link");
        assert_eq!(model.joints[0].child_link, "link1");
        assert_eq!(model.joints[0].joint_type, UrdfJointType::Revolute);
        assert_eq!(model.joints[0].origin.xyz, [0.0, 0.0, 1.0]);
        assert_eq!(model.joints[0].axis, [0.0, 0.0, 1.0]);
    }

    #[test]
    fn parse_fixed_joint() {
        let model = parse_urdf(FIXED_JOINT_URDF).unwrap();
        assert_eq!(model.joints[0].joint_type, UrdfJointType::Fixed);
        assert_eq!(model.joints[0].origin.xyz, [0.0, 0.0, 0.5]);
    }

    #[test]
    fn parse_invalid_xml_returns_error() {
        let result = parse_urdf("<robot><link name='a'><broken");
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_robot() {
        let model = parse_urdf("<robot name='empty'></robot>").unwrap();
        assert_eq!(model.name, "empty");
        assert!(model.links.is_empty());
        assert!(model.joints.is_empty());
    }

    // -- Forward kinematics tests --

    #[test]
    fn fk_zero_angles() {
        let model = parse_urdf(SIMPLE_URDF).unwrap();
        let angles = HashMap::new(); // all zero
        let positions = forward_kinematics(&model, &angles).unwrap();

        // base_link at origin.
        let base = positions["base_link"];
        assert!((base[0]).abs() < 1e-10);
        assert!((base[1]).abs() < 1e-10);
        assert!((base[2]).abs() < 1e-10);

        // link1 at (0, 0, 1) — joint1 origin translation.
        let link1 = positions["link1"];
        assert!((link1[0]).abs() < 1e-10);
        assert!((link1[1]).abs() < 1e-10);
        assert!((link1[2] - 1.0).abs() < 1e-10);

        // link2 at (1, 0, 1) — joint2 adds (1,0,0) in link1 frame.
        let link2 = positions["link2"];
        assert!((link2[0] - 1.0).abs() < 1e-10);
        assert!((link2[1]).abs() < 1e-10);
        assert!((link2[2] - 1.0).abs() < 1e-10);
    }

    #[test]
    fn fk_revolute_90_degrees() {
        let model = parse_urdf(SIMPLE_URDF).unwrap();
        let mut angles = HashMap::new();
        // Rotate joint1 by 90° around Z-axis.
        angles.insert("joint1".to_string(), std::f64::consts::FRAC_PI_2);

        let positions = forward_kinematics(&model, &angles).unwrap();

        // link1 is still at (0, 0, 1) — rotation doesn't affect its own position.
        let link1 = positions["link1"];
        assert!((link1[2] - 1.0).abs() < 1e-10);

        // link2: joint2 offset (1, 0, 0) in link1's rotated frame.
        // After 90° Z rotation, (1,0,0) becomes (0,1,0).
        // So link2 should be at (0, 1, 1).
        let link2 = positions["link2"];
        assert!(
            (link2[0]).abs() < 1e-10,
            "link2.x should be ~0, got {}",
            link2[0]
        );
        assert!(
            (link2[1] - 1.0).abs() < 1e-10,
            "link2.y should be ~1, got {}",
            link2[1]
        );
        assert!(
            (link2[2] - 1.0).abs() < 1e-10,
            "link2.z should be ~1, got {}",
            link2[2]
        );
    }

    #[test]
    fn fk_revolute_180_degrees() {
        let model = parse_urdf(SIMPLE_URDF).unwrap();
        let mut angles = HashMap::new();
        angles.insert("joint1".to_string(), std::f64::consts::PI);

        let positions = forward_kinematics(&model, &angles).unwrap();

        // After 180° Z rotation, (1,0,0) becomes (-1,0,0).
        // link2 at (-1, 0, 1).
        let link2 = positions["link2"];
        assert!(
            (link2[0] + 1.0).abs() < 1e-10,
            "link2.x should be ~-1, got {}",
            link2[0]
        );
        assert!((link2[1]).abs() < 1e-10);
        assert!((link2[2] - 1.0).abs() < 1e-10);
    }

    #[test]
    fn fk_fixed_joint() {
        let model = parse_urdf(FIXED_JOINT_URDF).unwrap();
        let positions = forward_kinematics(&model, &HashMap::new()).unwrap();

        let sensor = positions["sensor"];
        assert!((sensor[0]).abs() < 1e-10);
        assert!((sensor[1]).abs() < 1e-10);
        assert!((sensor[2] - 0.5).abs() < 1e-10);
    }

    #[test]
    fn fk_two_joint_rotation() {
        let model = parse_urdf(SIMPLE_URDF).unwrap();
        let mut angles = HashMap::new();
        // Both joints at 90°.
        angles.insert("joint1".to_string(), std::f64::consts::FRAC_PI_2);
        angles.insert("joint2".to_string(), std::f64::consts::FRAC_PI_2);

        let positions = forward_kinematics(&model, &angles).unwrap();

        // link1 at (0, 0, 1).
        // link2: joint2 origin (1,0,0) in link1 frame, rotated 90° by joint1.
        // That puts joint2 frame at (0, 1, 1).
        // Then joint2 rotates another 90°, but the link2 has no further offset,
        // so link2 is at (0, 1, 1).
        let link2 = positions["link2"];
        assert!(
            (link2[0]).abs() < 1e-10,
            "link2.x should be ~0, got {}",
            link2[0]
        );
        assert!(
            (link2[1] - 1.0).abs() < 1e-10,
            "link2.y should be ~1, got {}",
            link2[1]
        );
    }

    // -- Transform tests --

    #[test]
    fn identity_transform() {
        let tf = Transform::default();
        let m = tf.to_matrix();
        for i in 0..4 {
            for j in 0..4 {
                let expected = if i == j { 1.0 } else { 0.0 };
                assert!(
                    (m[i][j] - expected).abs() < 1e-12,
                    "identity[{i}][{j}] = {} (expected {expected})",
                    m[i][j]
                );
            }
        }
    }

    #[test]
    fn translation_only_transform() {
        let tf = Transform {
            xyz: [1.0, 2.0, 3.0],
            rpy: [0.0, 0.0, 0.0],
        };
        let m = tf.to_matrix();
        assert!((m[0][3] - 1.0).abs() < 1e-12);
        assert!((m[1][3] - 2.0).abs() < 1e-12);
        assert!((m[2][3] - 3.0).abs() < 1e-12);
    }

    // -- No root link --

    #[test]
    fn fk_no_root_returns_error() {
        // All links are children — no root.
        let model = UrdfModel {
            name: "broken".into(),
            links: vec![UrdfLink { name: "a".into() }, UrdfLink { name: "b".into() }],
            joints: vec![
                UrdfJoint {
                    name: "j1".into(),
                    joint_type: UrdfJointType::Fixed,
                    parent_link: "b".into(),
                    child_link: "a".into(),
                    origin: Transform::default(),
                    axis: [0.0, 0.0, 1.0],
                },
                UrdfJoint {
                    name: "j2".into(),
                    joint_type: UrdfJointType::Fixed,
                    parent_link: "a".into(),
                    child_link: "b".into(),
                    origin: Transform::default(),
                    axis: [0.0, 0.0, 1.0],
                },
            ],
        };
        let result = forward_kinematics(&model, &HashMap::new());
        assert!(result.is_err());
    }
}
